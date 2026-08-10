# Componenta Auth

Authentication contracts and HTTP building blocks for Componenta applications on PHP 8.4+.

The secure browser profile is a stateful HttpOnly session. JWT access tokens remain short-lived signed credentials; opaque refresh tokens are stateful grants with atomic rotation and replay compromise.

## Installation

```bash
composer require componenta/auth
```

Runtime requirements include `ext-mbstring`, PSR-7/15/17, and storage adapters for the mechanisms an application enables.

## Explicit composition

Authentication strategy order is part of the security policy and must be configured explicitly:

```php
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\SessionStrategy;

return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
        ],
        'events' => true,
    ],
];
```

`AuthenticatorFactory` rejects an empty list, duplicates, missing services and services that do not implement `AuthenticationStrategyInterface`. The package supports Componenta DI 2 and 3.

## Credential lifecycle invariants

- Credential removal is terminal for an HTTP request: logout cannot be overwritten by a pending session or remember-me rotation.
- Remember-me termination and regeneration listeners are enabled by default and are fail-closed security participants.
- Refresh rotation is one store-level atomic transition with durable family compromise.
- OTP attempts, comparison and consume operate on one locked/versioned challenge.
- Successful password reset invalidates every pre-reset long-lived credential.
- Raw passwords, OTPs and bearer/refresh tokens never enter generic auth events.
- Token responses use `Cache-Control: no-store` and `Pragma: no-cache`.

## Session performance

`SessionStrategy` and `RememberMeStrategy` attach the resolved `SessionInterface` to `AuthenticationResult::$attributes`; `TouchSessionMiddleware` reuses it instead of performing another lookup. Activity writes are conditionally throttled using `auth.session.touchInterval` (default 60 seconds). Expired-session cleanup is bounded and scheduled outside the request path.

## Application-owned security ports

Applications provide adapters for:

- `RefreshTokenStoreInterface`, including `rotateAtomically()` and `revokeAllForUser()`;
- `CodeStoreInterface::verifyAndConsume()`;
- `PasswordResetServiceInterface` for the complete account-recovery transition;
- `TokenRequestQueueInterface` and `OtpRequestQueueInterface` for uniform asynchronous delivery;
- `SessionCleanupSchedulerInterface` for out-of-request garbage collection.

See [MIGRATION-v2.md](MIGRATION-v2.md) for breaking changes and adapter requirements.

## Public failures and audit context

`DeniedReasonInterface::$attributes` is trusted audit context. The default `DeniedResponseFactory` emits only the stable `error` code. Public details require explicit opt-in through `PublicDeniedReasonInterface`.

Normal authentication failure is represented by `DeniedReasonInterface`. Infrastructure, invalid configuration and invalid request shape are exceptions and should be mapped by the application boundary.
