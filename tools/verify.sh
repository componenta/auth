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
for part in .auth-v2-review.part-*; do
    wc -c "$part"
    sha256sum "$part"
done

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

while IFS= read -r path; do
    if [[ -n "$path" ]]; then
        rm -rf -- "$path"
    fi
done < "$work/unpacked/delete-list.txt"

cp -a "$work/unpacked/replacement/." .
rm -f .auth-v2-review.part-* .auth-v2-review.ready
rm -f .github/workflows/apply-auth-v2-review.yml

composer update --with 'componenta/di:2.*' --prefer-dist --no-interaction --no-progress
bash tools/verify.sh

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
