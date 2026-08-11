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
- application adapters for the enabled stores and delivery queues.

## One canonical identity

Every authenticated subject is a `Componenta\Identity\IdentityInterface`. Its UUID is the only authentication subject identifier:

```php
$subjectId = $identity->uuid->toString();
```

There is no second auth-specific ID contract. Sessions, remember-me credentials, one-time tokens, refresh grants and JWT `sub` must all use the same UUID string. A persistence adapter may map it to an internal database key, but that mapping is not part of the auth API.

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

`AuthenticatorFactory` preserves the configured order and fails fast for an empty list, duplicates, missing services or values that do not implement `AuthenticationStrategyInterface`.

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
- rechecks expiration when bounded cleanup deletes previously selected rows;
- bounds cleanup batches and session-ID inputs.

Session metadata is exposed through `$session->attributes`. `getAttribute()` distinguishes an absent key from an explicitly stored `null` value.

`SessionCollection::pluck()` accepts declared session properties or metadata attributes and rejects unknown keys.

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
    ],
],
```

Validation checks signature, exact profile values, `iat`, `nbf`, `exp` and the configured maximum access-token lifetime. Signers emit an explicit `typ` header and do not allow custom claims to replace registered claims.

HMAC secrets must be at least 32/48/64 bytes for HS256/HS384/HS512 respectively.

Refresh token IDs and family IDs contain 32–64 random bytes. `RefreshTokenStoreInterface::rotateAtomically()` remains the storage-level security boundary. A rotated result must contain the exact successor requested by the manager, with the expected expiry and active state.

All access/refresh responses include:

```text
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
```

## OTP and one-time delivery

`CodeStoreInterface::verifyAndConsume()` combines attempt accounting, expiry, verifier comparison and consumption over the same locked or versioned challenge record. Expired and invalid outcomes remain distinguishable.

HTTP request handlers inject `TokenRequestQueueInterface` or `OtpRequestQueueInterface` directly and enqueue `TokenRequest`/`OtpRequest` messages. The former zero-logic requester wrappers have been removed.

User lookup, token/code generation, persistence and sender I/O execute in `TokenRequestProcessor` or `OtpRequestProcessor` outside the request thread.

The built-in one-time SQL manager replaces a subject challenge with one atomic UPSERT. Its table therefore requires a `UNIQUE` constraint on the canonical subject UUID column. OTP stores remain application adapters and must implement the atomic `verifyAndConsume()` contract over one locked or versioned record.

## Password reset

`PasswordResetServiceInterface` owns the complete recovery transition, including validation of the reset token and expensive password hashing. `PasswordResetResult::Success` means that the reset token was consumed, the password changed, and pre-reset session, remember-me and refresh credentials were durably or logically invalidated.

For separate stores, use a credential version plus transactional outbox and idempotent retry rather than reporting partial success.

## Events and public errors

Generic authentication events contain the payload type, never the raw password, OTP, bearer token or refresh token.

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
| `ConfigKey::JWT` | Explicit JWT and refresh profile. |
| `ConfigKey::DENIED` | HTTP denial status mapping. |
| `ConfigKey::LISTENERS` | Authentication event listeners. |

## Migration

Version 2 contains intentional breaking security and API changes. See [MIGRATION-v2.md](MIGRATION-v2.md). Do not emulate `rotateAtomically()` or `verifyAndConsume()` with the former sequential operations; doing so restores the races these contracts remove.
