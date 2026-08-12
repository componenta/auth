#!/usr/bin/env bash
set -euo pipefail

composer validate --strict
composer check-platform-reqs
composer lint

for removed in \
    AuthSubject \
    AuthSubjectInterface \
    RememberMeAwareInterface \
    SessionAwareInterface \
    PublicDeniedReasonInterface \
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

if grep -R --line-number --fixed-strings 'currentSessionId' src; then
    echo 'Request-local currentSessionId must not be stored on an identity.' >&2
    exit 1
fi

if grep -R --line-number -E 'getAuthSubjectId\(|isEmpty\(|shouldClear\(|payloads\(|publicDetails|isRevoked\(' src tests; then
    echo 'Legacy getter/capability state API is still referenced.' >&2
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
