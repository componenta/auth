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
    OtpRequester \
    AuthenticationAttemptedListenerInterface \
    AuthenticationSucceededListenerInterface \
    AuthenticationDeniedListenerInterface \
    LoggedOutListenerInterface \
    SessionRegeneratedListenerInterface \
    SessionsTerminatedListenerInterface \
    AllSessionsTerminatedListenerInterface
do
    if grep -R --line-number --fixed-strings "$removed" src tests; then
        echo "Removed symbol still referenced: $removed" >&2
        exit 1
    fi
done

for removed_file in \
    src/RememberMe/RememberMeToken.php \
    src/Factory/ListenerFactory.php \
    src/Http/Strategy/MagicLink/Denied/TokenAlreadyUsed.php \
    src/Http/Strategy/MagicLink/Denied/TokenExpired.php \
    src/Http/Strategy/Otp/Denied/CodeExpired.php \
    src/Http/Strategy/Otp/Denied/TooManyAttempts.php
do
    if [[ -e "$removed_file" ]]; then
        echo "Removed source file still exists: $removed_file" >&2
        exit 1
    fi
done

if grep -R --line-number -E '(^|[^[:alnum:]_])(RememberMeToken|ListenerFactory|TokenAlreadyUsed|TokenExpired)([^[:alnum:]_]|$)' src tests; then
    echo 'Removed security-domain symbol is still referenced.' >&2
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

if grep -R --line-number -- '->payloads' src tests; then
    echo 'Credential transport state must not expose queued bearer payloads.' >&2
    exit 1
fi

if grep -R --line-number --fixed-strings 'new Clock()' src/Event; then
    echo 'Event DTOs must receive timestamps from owning clock services.' >&2
    exit 1
fi

if grep -R --line-number -E 'RememberMeTokenManagerInterface.*consume|->consume\(' src/Http/Strategy/RememberMe src/RememberMe; then
    echo 'Delete-on-consume remember-me rotation must not return.' >&2
    exit 1
fi

if compgen -G '.auth-v2-review.part-*' >/dev/null; then
    echo 'Temporary staging payload remains.' >&2
    exit 1
fi

for forbidden in .auth-v2-review.ready .github/workflows/apply-auth-v2-review.yml .tmp-noop .restore-marker; do
    if [[ -e "$forbidden" ]]; then
        echo "Temporary staging artifact remains: $forbidden" >&2
        exit 1
    fi
done

if grep -R --line-number -E 'function (create|all|terminateAll|revokeAllForSubject|replaceForSubject)\(int\|string' src; then
    echo 'Credential ownership APIs must use the canonical UUID contract.' >&2
    exit 1
fi

for handler in \
    src/Http/Strategy/MagicLink/VerifyHandler.php \
    src/Http/Strategy/Jwt/MagicLink/TokenHandler.php
do
    if ! grep -q --fixed-strings 'MagicLinkResponseHeaders::apply' "$handler"; then
        echo "Magic-link verification response is missing referrer hardening: $handler" >&2
        exit 1
    fi
done

if ! grep -q --fixed-strings "withHeader('Referrer-Policy', 'no-referrer')" src/Http/Strategy/MagicLink/MagicLinkResponseHeaders.php; then
    echo 'Magic-link response hardening must enforce Referrer-Policy: no-referrer.' >&2
    exit 1
fi

if ! grep -q --fixed-strings 'private ReplacingPayloadStorage $storage' src/Http/Strategy/MagicLink/VerifyHandler.php; then
    echo 'Public magic-link session verification must require replacing credential storage.' >&2
    exit 1
fi

if ! grep -q --fixed-strings 'CompensatingRememberMeStrategy::class' src/ConfigProvider.php; then
    echo 'Discard-safe remember-me strategy must have a Componenta factory binding.' >&2
    exit 1
fi

if ! grep -q --fixed-strings 'Raw %s cannot be placed directly in the middleware strategy chain' src/Factory/AuthenticatorFactory.php; then
    echo 'AuthenticatorFactory must reject raw remember-me strategy composition.' >&2
    exit 1
fi

if ! grep -q --fixed-strings 'onDiscard' src/Http/Strategy/RememberMe/CompensatingRememberMeStrategy.php; then
    echo 'Discard-safe remember-me strategy must compensate unpublished rotations.' >&2
    exit 1
fi

for mutator in \
    src/Http/CredentialTransportState.php \
    src/Http/Handler/LogoutHandler.php
do
    if ! grep -q --fixed-strings 'CredentialResponseHeaders::apply' "$mutator"; then
        echo "Credential mutation path is missing no-store hardening: $mutator" >&2
        exit 1
    fi
done

if [[ ! -f resources/schema/mysql-8.4.sql ]]; then
    echo 'Canonical MySQL 8.4 auth schema is missing.' >&2
    exit 1
fi

for required in \
    'id VARBINARY(512)' \
    'user_agent VARBINARY(1024)' \
    'destination VARBINARY(320)' \
    'family_id VARCHAR(128)' \
    'idx_otp_expiry' \
    'idx_refresh_family_expiry' \
    'idx_sessions_cleanup_absolute'
do
    if ! grep -q --fixed-strings "$required" resources/schema/mysql-8.4.sql; then
        echo "Canonical MySQL schema is missing required invariant: $required" >&2
        exit 1
    fi
done

if grep -q --fixed-strings 'MAX(' src/Http/Strategy/Jwt/DatabaseRefreshTokenHousekeeper.php; then
    echo 'Refresh cleanup must select candidates from indexed family retention state, not aggregate token history.' >&2
    exit 1
fi

for signer in \
    src/Http/Strategy/Jwt/HmacSigner.php \
    src/Http/Strategy/Jwt/RsaSigner.php
do
    if ! grep -q --fixed-strings 'BearerCredential::' "$signer"; then
        echo "JWT signer does not enforce the shared bearer transport contract: $signer" >&2
        exit 1
    fi
done

while IFS= read -r action; do
    [[ -z "$action" ]] && continue

    case "$action" in
        ./*|docker://*)
            continue
            ;;
    esac

    ref="${action##*@}"
    if [[ "$action" == "$ref" || ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        echo "GitHub Actions dependency must be pinned to a full commit SHA: $action" >&2
        exit 1
    fi
done < <(
    { grep -R -h -E '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+' .github/workflows || true; } \
        | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+([^[:space:]#]+).*/\1/'
)

while IFS= read -r image; do
    [[ -z "$image" ]] && continue

    if [[ ! "$image" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "Workflow container image must be pinned to an immutable digest: $image" >&2
        exit 1
    fi
done < <(
    { grep -R -h -E '^[[:space:]]*image:[[:space:]]+' .github/workflows || true; } \
        | sed -E 's/^[[:space:]]*image:[[:space:]]+([^[:space:]#]+).*/\1/'
)

composer test
composer phpstan
composer audit --no-interaction
git diff --check
