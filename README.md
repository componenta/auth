# Componenta Auth

Authentication contracts and PSR-7/PSR-15 building blocks for Componenta applications on PHP 8.4+.

The package supports password login, stateful sessions, remember-me cookies, signed JWT access tokens with stateful opaque refresh grants, OTP, magic links, password reset and authentication lifecycle events.

For browser applications, the recommended profile is a stateful `HttpOnly` session. JWT access tokens should be short-lived; opaque refresh tokens remain server-side grants with atomic rotation and replay detection.

## Installation

```bash
composer require componenta/auth
```

`Componenta\Auth\ConfigProvider` is declared in `extra.componenta.config-providers`.

## Runtime requirements

- PHP 8.4 or newer;
- `ext-mbstring`;
- PSR-7, PSR-15 and PSR-17 implementations;
- Componenta DI 2 or 3;
- Cycle Database for the built-in session, remember-me, one-time, refresh and OTP stores;
- application adapters for delivery queues, password reset and any store intentionally replaced by the application.

## One canonical identity

Every authenticated subject is a `Componenta\Identity\IdentityInterface`. Its UUID is the only authentication subject identifier:

```php
$subjectId = $identity->uuid->toString();
```

There is no second auth-specific ID contract. Sessions, remember-me credentials, one-time tokens, OTP challenges, refresh grants and JWT `sub` must all use the same UUID string. A persistence adapter may map it to an internal database key, but that mapping is not part of the auth API.

## Explicit authenticator composition

Authentication strategy order is security-sensitive and must be configured explicitly:

```php
use Componenta\Auth\Http\Strategy\Jwt\JwtStrategy;
use Componenta\Auth\Http\Strategy\Password\PasswordStrategy;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\SessionStrategy;

return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
            PasswordStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
        'rememberMe' => [
            'enabled' => true,
        ],
    ],
];
```

`AuthenticatorFactory` preserves the configured order and fails fast for an empty list, duplicates, missing services or values that do not implement `AuthenticationStrategyInterface`. The built-in `RememberMeStrategy` is also rejected unless `auth.rememberMe.enabled=true`, because the feature requires its critical lifecycle listeners.

Password, OTP and magic-link HTTP verification handlers use this same `AuthenticatorInterface`; they no longer bypass the configured event decorator by invoking an individual strategy directly.

## Authentication result

`AuthenticationResult` exposes only typed state:

| Property | Meaning |
|---|---|
| `$subject` | An authenticated `IdentityInterface` or a `DeniedReasonInterface`. |
| `$transportPayload` | An optional response-side credential mutation. |
| `$session` | The verified request-local `SessionInterface`, when session authentication resolved one. |

The result no longer contains an open-ended attribute bag. Request-local session state is not written into the identity entity, which keeps singleton/ORM identities safe in long-running workers.

## PHP 8.4 property API

State is exposed as properties; methods remain for actions and lookups that accept input:

```php
$context->attributes;
$session->attributes;
$sessions->empty;
$transportState->empty;
$transportState->cleared;
$transportState->payloads;
$refreshToken->revoked;
```

Methods such as `getAttribute($name, $default)`, `find($id)`, `consume($token)`, `isExpired($now)`, `queue()` and `clear()` remain methods because they accept input or mutate state.

## Deterministic credential transport

`AuthenticationMiddleware` creates one request-scoped `CredentialTransportState` and applies it once after the downstream handler returns.

`clear()` is terminal. Deletion always wins over queued or future credential rotation. `LogoutHandler` therefore schedules the clear operation when terminal middleware is present; it does not also remove the same cookies itself.

## Sessions

`SessionStrategy` and `RememberMeStrategy` return the already verified `SessionInterface` through `AuthenticationResult::$session`. `TouchSessionMiddleware` reuses it and does not perform a second lookup.

The session manager:

- enforces idle and absolute expiry before touch;
- throttles activity writes with `auth.session.touchInterval`;
- uses a conditional update to avoid concurrent write amplification;
- keeps regeneration transactional and uses an optimistic claim on the old row;
- runs security-critical lifecycle participants inside the database transaction and best-effort observers only after commit;
- rechecks expiration when bounded cleanup deletes previously selected rows;
- bounds cleanup batches and session-ID inputs.

Session metadata is exposed through `$session->attributes`. `getAttribute()` distinguishes an absent key from an explicitly stored `null` value.

`SessionCollection::pluck()` accepts declared session properties or metadata attributes and rejects unknown keys.

## Primary database reads for credentials

Cycle Database can use separate READ and WRITE drivers. Replica lag is unacceptable for authentication state: a session that was terminated on the primary must not remain valid because a replica still contains the old row.

The built-in session, remember-me, one-time-token, refresh and OTP stores therefore pin credential-state reads to `DatabaseInterface::WRITE`. Read replicas may still be used for non-authoritative housekeeping selection when the subsequent write operation rechecks the security predicate on the primary.

Custom credential stores must preserve the same rule or provide an equivalent linearizable consistency guarantee.

## Remember-me credentials

Remember-me is disabled by default. When `auth.rememberMe.enabled` is true, the package automatically adds the termination and regeneration listeners required by the feature; both are critical lifecycle participants.

Remember-me tokens are 256-bit opaque values stored as SHA-256 representations. Consumption remains single-winner through an affected-row check. Bulk termination uses `revokeForSessions()` with bounded chunks. Nullable `session_id` rows are included in revoke-all-except operations.

Housekeeping uses `cleanup(int $limit): int`; it is bounded and intended for a worker or scheduler.

## Password authentication

The password provider receives only the normalized identity string:

```php
interface UserProviderInterface
{
    public function findByIdentity(
        string $identity,
    ): null|(IdentityInterface&PasswordAwareInterface);
}
```

The submitted password is visible only to the verifier. A dummy hash is prepared during service construction rather than on the first unknown-user request.

## JWT access tokens and refresh grants

JWT validation is an explicit profile. `issuer`, `audience` and token `type` are required; clock skew is bounded.

```php
'auth' => [
    'jwt' => [
        'issuer' => 'https://issuer.example',
        'audience' => 'componenta-api',
        'type' => 'at+jwt',
        'accessTtl' => 900,
        'refreshTtl' => 604800,
        'clockSkew' => 30,
        'refreshStore' => [
            'tokenTable' => 'refresh_tokens',
            'familyTable' => 'refresh_token_families',
        ],
    ],
],
```

Validation checks signature, exact profile values, `iat`, `nbf`, `exp` and the configured maximum access-token lifetime. Signers emit an explicit `typ` header and do not allow custom claims to replace registered claims.

HMAC secrets must be at least 32/48/64 bytes for HS256/HS384/HS512 respectively.

Refresh token IDs and family IDs contain 32–64 random bytes. The default `RefreshTokenStoreInterface` binding is `DatabaseRefreshTokenStore`.

The built-in refresh store:

- persists only SHA-256 representations of bearer token IDs;
- keeps a separate family row as the serialization point for rotation, replay handling and bulk revocation;
- performs presented-token consumption and successor creation in one database transaction;
- rolls the presented-token claim back if successor persistence fails;
- marks the family compromised on replay and revokes every active descendant;
- pins security-state reads to the primary/write connection.

The schema must enforce at least:

```text
refresh_token_families
  family_id       PRIMARY KEY or UNIQUE
  user_id         NOT NULL, indexed
  compromised_at  nullable
  lock_nonce      NOT NULL

refresh_tokens
  token_hash      PRIMARY KEY or UNIQUE
  family_id       NOT NULL, indexed/FK to refresh_token_families.family_id
  user_id         NOT NULL, indexed
  expires_at      NOT NULL
  consumed_at     nullable
  revoked_at      nullable
```

Configured table and column names may differ. `token_hash` contains the 64-character SHA-256 hex representation, never the bearer token itself.

`RefreshTokenStoreInterface::rotateAtomically()` remains the contract for custom implementations. A rotated result must contain the exact successor requested by the manager, with the expected expiry and active state. A custom implementation must provide equivalent family serialization and replay guarantees.

All access/refresh responses include:

```text
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
```

## OTP and one-time delivery

`CodeStoreInterface::verifyAndConsume()` combines attempt accounting, expiry, verifier comparison and consumption over one versioned challenge.

The default `CodeStoreInterface` binding is `DatabaseCodeStore`. It never persists the plaintext numeric code. Instead it stores `HMAC-SHA-256(destination || NUL || code)` with an application secret:

```php
'auth' => [
    'otp' => [
        'hmacKey' => $_ENV['AUTH_OTP_HMAC_KEY'], // at least 32 bytes
        'store' => [
            'table' => 'otp_codes',
        ],
    ],
],
```

The default empty `auth.otp.hmacKey` is intentionally unusable; resolving the built-in SQL store fails fast until the application supplies a secret of at least 32 bytes. Use a dedicated secret rather than reusing a JWT signing key.

`DatabaseCodeStore` uses a random `challenge_id` as the optimistic version. Invalid-attempt updates and successful/expired deletes include that version. If a challenge is replaced during verification, the stale operation stops instead of charging an attempt against or consuming the replacement.

The OTP schema must enforce one current challenge per destination:

```text
otp_codes
  destination   PRIMARY KEY or UNIQUE
  user_id       NOT NULL
  challenge_id  NOT NULL
  verifier      NOT NULL
  expires_at    NOT NULL
  attempts      NOT NULL
```

The built-in one-time SQL manager used by magic links/password-reset delivery replaces a subject challenge with one atomic UPSERT. Its table therefore requires a `UNIQUE` constraint on the canonical subject UUID column.

HTTP request handlers inject `TokenRequestQueueInterface` or `OtpRequestQueueInterface` directly and enqueue `TokenRequest`/`OtpRequest` messages. User lookup, token/code generation, persistence and sender I/O execute in `TokenRequestProcessor` or `OtpRequestProcessor` outside the request thread.

Applications that replace `CodeStoreInterface` must provide equivalent single-winner, attempt-accounting, replacement-isolation and primary-read guarantees.

## Password reset

`PasswordResetServiceInterface` owns the complete recovery transition, including validation of the reset token and expensive password hashing. `PasswordResetResult::Success` means that the reset token was consumed, the password changed, and pre-reset session, remember-me and refresh credentials were durably or logically invalidated.

The package cannot manufacture a cross-store transaction around an application-owned password repository. When password state and credentials live in separate stores, use a credential version plus transactional outbox and idempotent retry rather than reporting partial success.

## Events and public errors

Generic authentication events contain the payload type, never the raw password, OTP, bearer token or refresh token.

Security-critical session lifecycle listeners run before best-effort observers. For database-backed session transitions, critical listeners participate in the transaction; observers only see an event after commit.

`DeniedReasonInterface::$attributes` is trusted audit context. The default response exposes only the stable error code. A reason may explicitly expose allowlisted scalar fields through `PublicDeniedReasonInterface::$publicDetails`.

## Input and cookie validation

Authentication inputs are type-checked and bounded before hashing, provider lookup or storage access. Malformed credentials are represented by `InvalidPayloadException` without retaining the credential payload inside the exception.

Built-in HTTP handlers that invoke strict extractors must run behind `InvalidPayloadMiddleware` or an application-level equivalent that maps `InvalidPayloadException` to a stable 400 response. Omitting this mapping makes malformed-client behavior depend on the application's global exception handler and is not a supported production composition.

`CookieTransport` validates cookie names, path, domain, `SameSite`, `__Secure-`/`__Host-` requirements and credential lengths. `SameSite=None` requires `Secure`.

## Main configuration keys

| Key | Purpose |
|---|---|
| `ConfigKey::AUTH` | Root auth configuration. |
| `ConfigKey::STRATEGIES` | Ordered strategy service IDs. |
| `ConfigKey::EVENTS` | Eventing authenticator decorator. |
| `ConfigKey::SESSION` | Session persistence and touch settings. |
| `ConfigKey::REMEMBER_ME` | Remember-me feature flag and persistence settings; disabled by default. |
| `ConfigKey::OTP` | OTP store settings and dedicated HMAC verifier key. |
| `ConfigKey::JWT` | Explicit JWT profile and built-in refresh-store settings. |
| `ConfigKey::DENIED` | HTTP denial status mapping. |
| `ConfigKey::LISTENERS` | Authentication event listeners. |

## Migration

Version 2 contains intentional breaking security and API changes. See [MIGRATION-v2.md](MIGRATION-v2.md). Do not emulate `rotateAtomically()` or `verifyAndConsume()` with the former sequential operations; doing so restores the races these contracts remove.

Applications with a separate Cycle READ driver must also upgrade all credential-state consumers together: v2 deliberately reads authentication state from the primary/write driver so replica lag cannot resurrect revoked credentials.
