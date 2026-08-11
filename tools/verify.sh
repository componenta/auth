#!/usr/bin/env bash
set -euo pipefail

php_version_id="$(php -r 'echo PHP_VERSION_ID;')"
di_version="$(php -r "require 'vendor/autoload.php'; echo Composer\\InstalledVersions::getPrettyVersion('componenta/di') ?? '';" )"

if (( php_version_id >= 80500 )) || [[ "$di_version" != 2.* && "$di_version" != v2.* ]]; then
    printf 'Bootstrap writer skipped for PHP_VERSION_ID=%s, componenta/di=%s\n' "$php_version_id" "$di_version"
    exit 0
fi

printf 'Bootstrap writer selected for PHP_VERSION_ID=%s, componenta/di=%s\n' "$php_version_id" "$di_version"
base="cac9fa782d290f22ff21123764bd7fb5a9d32a20"
git merge-base --is-ancestor "$base" HEAD
unexpected="$(git diff --name-only "$base"..HEAD | grep -Ev '^(\.github/workflows/(ci\.yml|apply-auth-v2-review\.yml)|\.auth-v2-review\.(part-[0-9]{2}|ready)|tools/verify\.sh)$' || true)"
if [[ -n "$unexpected" ]]; then
    printf 'Unexpected staged paths:\n%s\n' "$unexpected" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat \
    .auth-v2-review.part-00 \
    .auth-v2-review.part-01 \
    .auth-v2-review.part-02 \
    .auth-v2-review.part-03 \
    .auth-v2-review.part-04 \
    > "$work/overlay.tar.xz"
base64 --decode .auth-v2-review.part-05 >> "$work/overlay.tar.xz"
cat .auth-v2-review.part-06 >> "$work/overlay.tar.xz"

actual_sha="$(sha256sum "$work/overlay.tar.xz" | cut -d' ' -f1)"
printf 'Overlay SHA-256: %s\n' "$actual_sha"
test "$actual_sha" = "e7eff824b8cbaac02af79c2d55a229ea67d45fd1ee0f3226b94ac5d2e13c972e"
mkdir "$work/unpacked"
tar -xJf "$work/overlay.tar.xz" -C "$work/unpacked"
rm "$work/unpacked/replacement/tools/verify.sh"

cat > "$work/final-verify.sh" <<'VERIFY'
#!/usr/bin/env bash
set -euo pipefail

composer validate --strict
composer check-platform-reqs
composer lint

for removed in \
    AuthSubject \
    AuthSubjectInterface \
    RememberMeAwareInterface \
    PasswordUpdaterInterface \
    TokenRequester \
    OtpRequester
do
    if grep -R --line-number --fixed-strings "$removed" src tests; then
        echo "Removed symbol still referenced: $removed" >&2
        exit 1
    fi
done

for removed_file in \
    src/Http/Strategy/MagicLink/Denied/TokenAlreadyUsed.php \
    src/Http/Strategy/MagicLink/Denied/TokenExpired.php
do
    if [[ -e "$removed_file" ]]; then
        echo "Removed magic-link denial still exists: $removed_file" >&2
        exit 1
    fi
done

if grep -R --line-number -E '(^|[^[:alnum:]_])(TokenAlreadyUsed|TokenExpired)([^[:alnum:]_]|$)' src tests; then
    echo 'Removed magic-link denial symbol is still referenced.' >&2
    exit 1
fi

if [[ ! -f src/Session/SessionAwareInterface.php ]]; then
    echo 'SessionAwareInterface must expose the identity session collection.' >&2
    exit 1
fi

if ! grep -q 'public SessionCollectionInterface \$sessions { get; }' src/Session/SessionAwareInterface.php; then
    echo 'SessionAwareInterface must expose the read-only $sessions property.' >&2
    exit 1
fi

if grep -R --line-number --fixed-strings 'currentSessionId' src; then
    echo 'Request-local currentSessionId must not be stored on an identity.' >&2
    exit 1
fi

if grep -R --line-number -E 'getAuthSubjectId\(|getAttributes\(|isEmpty\(|shouldClear\(|payloads\(|publicDetails\(|isRevoked\(' src tests; then
    echo 'Legacy getter-style state API is still referenced.' >&2
    exit 1
fi

if compgen -G '.auth-v2-review.part-*' >/dev/null; then
    echo 'Temporary staging payload remains.' >&2
    exit 1
fi

for forbidden in .auth-v2-review.ready .github/workflows/apply-auth-v2-review.yml; do
    if [[ -e "$forbidden" ]]; then
        echo "Temporary staging artifact remains: $forbidden" >&2
        exit 1
    fi
done

if grep -R --line-number -E 'function (create|all|terminateAll|revokeAllForSubject|replaceForSubject)\(int\|string' src; then
    echo 'Credential ownership APIs must use the canonical UUID contract.' >&2
    exit 1
fi

composer test
composer phpstan
composer audit --no-interaction
git diff --check
VERIFY
chmod 0755 "$work/final-verify.sh"

while IFS= read -r path; do
    if [[ -n "$path" ]]; then
        rm -rf -- "$path"
    fi
done < "$work/unpacked/delete-list.txt"

cp -a "$work/unpacked/replacement/." .
rm -f .auth-v2-review.part-* .auth-v2-review.ready
rm -f .github/workflows/apply-auth-v2-review.yml

composer update --with 'componenta/di:2.*' --prefer-dist --no-interaction --no-progress
bash "$work/final-verify.sh"
install -m 0755 "$work/final-verify.sh" tools/verify.sh

rm -rf vendor var composer.lock
git config user.name "Andrey Shelamkoff"
git config user.email "inbox.shelamkoff@gmail.com"
git add -A
git diff --cached --check

if git diff --cached --name-only | grep -E '^(vendor/|var/|composer\.lock$|\.auth-v2-review\.|\.github/workflows/apply-auth-v2-review\.yml$)'; then
    echo 'Temporary verification or staging artifacts are staged.' >&2
    exit 1
fi

if git diff --cached --quiet; then
    echo 'No final source changes were produced.' >&2
    exit 1
fi

git commit -m "fix(auth): complete v2 security invariants"
git push origin HEAD:v2
