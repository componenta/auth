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

if [[ ! -f src/Session/SessionAwareInterface.php ]]; then
    echo 'SessionAwareInterface must remain as the capability exposing all sessions.' >&2
    exit 1
fi

if grep -R --line-number --fixed-strings 'currentSessionId' src tests; then
    echo 'Request-local currentSessionId must not be stored on an identity.' >&2
    exit 1
fi

if grep -R --line-number -E 'getAuthSubjectId\(|getAttributes\(|isEmpty\(|shouldClear\(|payloads\(|publicDetails\(|isRevoked\(' src tests; then
    echo 'Legacy getter-style state API is still referenced.' >&2
    exit 1
fi

composer test
composer phpstan
composer audit --no-interaction
git diff --check
