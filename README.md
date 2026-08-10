# Componenta Auth

Authentication contracts and PSR-7/PSR-15 building blocks for Componenta applications on PHP 8.4+.

The package supports password login, stateful sessions, remember-me cookies, signed JWT access tokens with opaque refresh grants, OTP, magic links, password reset and authentication lifecycle events. Authentication mechanisms are strategies; credential lifecycle and transport are separate security layers.

For browser-first applications the recommended profile is a stateful `HttpOnly` session. JWT access tokens should be short-lived, while opaque refresh tokens remain stateful grants with atomic rotation and replay compromise.

## Installation

```bash
composer require componenta/auth
```

`Componenta\Auth\ConfigProvider` is declared in `extra.componenta.config-providers`. When `componenta/composer-plugin` is installed, the provider can be discovered automatically.

## Requirements

- PHP 8.4 or newer;
- `ext-mbstring`;
- PSR-7 / PSR-15 / PSR-17 implementations for the HTTP layer;
- Componenta DI 2 or 3;
- application storage adapters for the enabled authentication mechanisms.

## Explicit authenticator composition

Strategy order is security-sensitive and must be configured explicitly:

```php
use Componenta\Auth\Http\Strategy\Jwt\JwtStrategy;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\SessionStrategy;

return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
    ],
];
```

`AuthenticatorFactory` preserves the configured order and fails fast for an empty list, duplicate IDs, missing services or services that do not implement `AuthenticationStrategyInterface`.

Manual construction remains possible at a composition root:

```php
use Componenta\Auth\Authenticator;
use Componenta\Auth\Context;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Identity\IdentityInterface;

$authenticator = new Authenticator(
    $passwordStrategy,
    $sessionStrategy,
    $jwtStrategy,
);

$result = $authenticator->attempt($payload, new Context());

if ($result->subject instanceof IdentityInterface) {
    $identity = $result->subject;
}

if ($result->subject instanceof DeniedReasonInterface) {
    $reason = $result->subject;
}
```

`Authenticator` skips unsupported strategies, returns the first successful identity, returns the last denial when all supporting strategies deny, and throws `NoStrategyFoundException` when no strategy supports the payload.

## Authentication results

`AuthenticationResult` exposes:

| Property | Meaning |
|---|---|
| `$subject` | Authenticated `IdentityInterface` or `DeniedReasonInterface`. |
| `$transportPayload` | Optional response-side credential mutation prepared by a strategy. |
| `$attributes` | Verified request-scoped state, such as the already resolved `SessionInterface`. |

There is no separate success flag. Success is represented by an `IdentityInterface` subject.

## Strategy contract

```php
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;

final readonly class ApiKeyStrategy implements AuthenticationStrategyInterface
{
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof ApiKeyPayload;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        // Return an identity or a denial reason.
    }
}
```

Normal authentication failure is data, not an exception. Strategies should return a denial result for invalid credentials and reserve exceptions for invalid configuration, malformed input or infrastructure failure.

## HTTP extraction and malformed input

HTTP extractors convert a PSR-7 request into strategy-specific payloads. Password and OTP extractors validate scalar types and input bounds before normalization, hashing, provider lookup or storage access. `remember` accepts only booleans, `0/1`, and allowlisted textual values.

Use `InvalidPayloadMiddleware`, or an equivalent application boundary, to map `InvalidPayloadException` to HTTP 400.

## Deterministic credential transport

`AuthenticationMiddleware` creates a request-scoped `CredentialTransportState`, attaches authentication state to the request and commits credential mutations once after the downstream handler returns.

`CredentialTransportState::clear()` is terminal: deletion always wins over queued or future rotation. This prevents a remember-me recovery or session-chain update from writing fresh authentication cookies after logout.

Custom credential-changing handlers can retrieve `CredentialTransportState::class` from the request attributes and call `clear()` when the final decision is to remove credentials.

## Sessions

Session support includes ID generation, database-backed persistence, idle and absolute expiration, bounded replacement chains, transactional regeneration and lifecycle events.

`SessionStrategy` and `RememberMeStrategy` attach the verified `SessionInterface` to the request. `TouchSessionMiddleware` reuses it rather than performing a second lookup.

Activity writes are conditionally throttled by `auth.session.touchInterval` (60 seconds by default). Set it to `0` only when an update on every request is intentionally required.

Expired-session cleanup is bounded through `SessionManagerInterface::cleanup(int $limit)`. `SessionGarbageCollectionMiddleware` only asks a `SessionCleanupSchedulerInterface` to enqueue work; it does not perform an unbounded delete in the HTTP request.

## Remember-me credentials

Remember-me tokens are random opaque credentials and are stored as SHA-256 representations. Consumption is single-winner through an affected-row check.

Termination and regeneration listeners are enabled by the package configuration and are critical synchronous security participants. Their failure is surfaced instead of silently reporting successful session termination. Bulk session termination uses `revokeForSessions()` rather than one delete per session.

## JWT access tokens and refresh grants

Access tokens are signed JWT credentials. Refresh tokens are stateful opaque grants.

A `RefreshTokenStoreInterface` implementation must provide:

- `storeInitial()` for the first token in a family;
- `rotateAtomically()` for lookup, expiry validation, revocation, successor creation and replay compromise in one serialized storage transition;
- `revoke()` and `revokeAllForUser()` for explicit and account-wide invalidation.

A compliant store needs durable family or grant state. When replay is detected, no active descendant may remain and no concurrent transaction may insert a new active descendant after compromise.

Responses containing access or refresh tokens always include:

```text
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
```

If a rotated grant resolves to a subject that no longer exists, the newly created successor is immediately revoked.

## OTP

`CodeStoreInterface::verifyAndConsume()` is the security boundary for OTP verification. Attempt accounting, expiry validation, verifier comparison and consume must operate on the same locked or versioned challenge record.

For a low-entropy OTP, production stores should persist a keyed verifier such as an HMAC instead of the canonical code when the backing store can be read independently.

## Magic links, OTP delivery and account recovery

Request endpoints enqueue opaque work through `TokenRequestQueueInterface` or `OtpRequestQueueInterface`. Account lookup, token/code creation, persistence and sender I/O run in `TokenRequestProcessor` / `OtpRequestProcessor` outside the HTTP request path. Known and unknown accounts therefore follow the same request-thread path.

Password reset is delegated to `PasswordResetServiceInterface`. `PasswordResetResult::Success` means one completed security transition:

- the reset token was consumed;
- the password was updated;
- old sessions were invalidated;
- remember-me credentials were invalidated;
- refresh grants were invalidated.

When stores are distributed, use a credential version plus transactional outbox and idempotent retry rather than reporting partial success.

## Events and public errors

`EventingAuthenticator` emits `AuthenticationAttempted`, `AuthenticationSucceeded` and `AuthenticationDenied` with the payload type, never the raw password, OTP, bearer token or refresh token.

Listeners that implement `CriticalEventListenerInterface` are fail-closed. Other observers such as metrics and notifications remain isolated from one another.

`DeniedReasonInterface::$attributes` is trusted audit context. The default `DeniedResponseFactory` publishes only the stable `error` code. A reason must explicitly implement `PublicDeniedReasonInterface` to expose allowlisted public details.

## HTTP middleware

The package provides:

- `InvalidPayloadMiddleware` — maps malformed authentication payloads to HTTP 400;
- `AuthenticationMiddleware` — extracts credentials, authenticates and commits transport state;
- `RequireAuthenticationMiddleware` — enforces an authenticated identity;
- `TouchSessionMiddleware` — regenerates and conditionally touches the verified session;
- `SessionGarbageCollectionMiddleware` — schedules bounded cleanup outside the request.

Applications remain responsible for route layout and for deployment-level controls such as CSRF protection and endpoint-specific rate limiting.

## Main configuration keys

| Key | Purpose |
|---|---|
| `ConfigKey::AUTH` | Root authentication configuration. |
| `ConfigKey::STRATEGIES` | Ordered authentication strategy service IDs. |
| `ConfigKey::EVENTS` | Enables or disables the eventing authenticator decorator. |
| `ConfigKey::SESSION` | Session manager and touch configuration. |
| `ConfigKey::REMEMBER_ME` | Remember-me persistence and cookie options. |
| `ConfigKey::JWT` | JWT access and refresh lifetimes and claims. |
| `ConfigKey::MAGIC_LINK` | Magic-link integration settings. |
| `ConfigKey::PASSWORD_RESET` | Password-reset integration settings. |
| `ConfigKey::DENIED` | HTTP denial response mapping. |
| `ConfigKey::LISTENERS` | Authentication event listener services. |

## Migration

Version 2 contains intentional breaking security contracts. Update storage adapters and application composition using [MIGRATION-v2.md](MIGRATION-v2.md). Do not emulate `rotateAtomically()` or `verifyAndConsume()` by calling the former methods sequentially; doing so preserves the races these contracts remove.
