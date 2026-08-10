#!/usr/bin/env bash
set -euo pipefail

composer validate --strict
composer check-platform-reqs
composer lint

for removed in \
    AuthSubject \
    AuthSubjectInterface \
    SessionAwareInterface \
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

if grep -R --line-number -E 'getAttributes\(|isEmpty\(|shouldClear\(|payloads\(' src tests; then
    echo 'Legacy getter-style state API is still referenced.' >&2
    exit 1
fi

composer test
composer phpstan
composer audit --no-interaction
