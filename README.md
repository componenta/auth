# Componenta Auth

Authentication contracts and HTTP-oriented authentication building blocks for Componenta applications.

Use this package when an application needs more than one authentication mechanism: password login, bearer/JWT tokens, session authentication, remember-me cookies, OTP, magic links, password reset, or auth lifecycle events. The package is strategy-based: each mechanism decides whether it supports a payload, attempts authentication, and returns either an authenticated identity or a denial reason.

## Installation

```bash
composer require componenta/auth
```

The package declares `Componenta\Auth\ConfigProvider` in `extra.componenta.config-providers`.
When `componenta/composer-plugin` is installed, the provider is added to the generated provider list automatically.

## Requirements

- PHP 8.4+
- PSR-7 / PSR-15 for HTTP middleware and handlers
- Storage adapters for the strategies you enable: sessions, remember-me tokens, refresh tokens, OTP codes, or password-reset tokens

## Related Packages

| Package | Why it matters here |
|---|---|
| `componenta/session` | Stores browser session state and session ids for session authentication. |
| `componenta/app-http` | Wires authentication middleware into HTTP applications that use PSR-7 requests and PSR-15 middleware. |
| `componenta/event` | Handles login, denial, logout, session regeneration, and session termination events. |
| `componenta/policy` | Uses the authenticated identity as the actor for authorization. |
| `componenta/di` | Builds strategies, token managers, middleware, and listeners from the container. |

## Core Flow

```php
use Componenta\Auth\Authenticator;
use Componenta\Auth\Context;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Identity\IdentityInterface;

$authenticator = new Authenticator(
    $passwordStrategy,
    $jwtStrategy,
    $sessionStrategy,
);

$result = $authenticator->attempt($payload, new Context());

if ($result->subject instanceof IdentityInterface) {
    $identity = $result->subject;
}

if ($result->subject instanceof DeniedReasonInterface) {
    $reason = $result->subject;
}
```

`Authenticator` iterates over registered strategies in order. Unsupported strategies are skipped. Supporting strategies are attempted until one returns an `IdentityInterface`. If every supporting strategy denies the payload, the last denial is returned. If no strategy supports the payload, `NoStrategyFoundException` is thrown.

`AuthenticationResult` has two public properties:

| Property | Meaning |
|---|---|
| `$subject` | Either the authenticated `IdentityInterface` or a `DeniedReasonInterface`. |
| `$transportPayload` | Optional object that must be persisted to the response transport, for example a rotated session or remember-me cookie payload. |

There is no separate boolean success flag. Consumers decide success by checking whether `$result->subject` is an `IdentityInterface`.

## Strategy Contract

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
        // Return AuthenticationResult with IdentityInterface on success,
        // or DeniedReasonInterface on failure.
    }
}
```

Strategies must be deterministic for a given payload and context. They should not throw for normal authentication failure; return a denial result instead.

## Payloads And HTTP Extraction

HTTP strategies are separated from payload extraction. A payload extractor reads a PSR-7 request and produces a strategy-specific payload object:

- bearer token payloads for `Authorization: Bearer ...`
- password payloads for login forms or JSON bodies
- session payloads
- OTP payloads
- magic-link verification payloads

This separation keeps strategies testable and lets applications define their own request shape without changing authentication logic.

## Sessions

Session support includes session contracts, session collection, session attributes, ID generation, device detection, and database-backed session management.

Use session authentication when the browser already has a session id and the application can resolve it to a user:

```php
$result = $sessionStrategy->attempt($sessionPayload, $context);
```

Session lifecycle events are available for login/logout, regeneration, and termination flows.

## Tokens

The package includes token helpers for:

- JWT access tokens and refresh tokens
- OTP request/verify flows
- magic-link request/verify flows
- password reset tokens
- remember-me tokens

Token managers own persistence and invalidation. Token handlers own signing/parsing and denial reasons such as expired, invalid, already used, or compromised tokens.

## Events

`EventingAuthenticator` decorates authentication attempts with events:

- `AuthenticationAttempted`
- `AuthenticationSucceeded`
- `AuthenticationDenied`
- `LoggedOut`
- `SessionRegenerated`
- `SessionsTerminated`
- `AllSessionsTerminated`

Listeners are resolved through `EventListenerProviderInterface`. Use events for audit logs, session cleanup, remember-me token rotation, notifications, and metrics.

## HTTP Middleware

The HTTP layer provides:

- `AuthenticationMiddleware`: attempts authentication and attaches auth state to the request/context.
- `RequireAuthenticationMiddleware`: rejects unauthenticated requests.
- `TouchSessionMiddleware`: updates session activity.
- `SessionGarbageCollectionMiddleware`: triggers storage cleanup.

The package does not prescribe route layout. Applications decide which routes are public and which routes require authentication.

`AuthenticationMiddleware` writes the result to PSR-7 request attributes:

| Attribute key | Value |
|---|---|
| `Componenta\Identity\IdentityInterface::class` | Present when authentication succeeds. |
| `Componenta\Auth\DeniedReasonInterface::class` | Present when a supporting strategy denies the request. |

If a strategy returns `$transportPayload`, the middleware requires a `PayloadStorageInterface`; otherwise it throws a `LogicException` because it cannot persist cookies or other response-side transport data.

## DI Registration

`ConfigProvider` registers factories, aliases, listeners, token handlers, session managers, middleware, and default configuration keys used by the Componenta application runtime. Only the strategies and adapters wired by the application are active.

The main configuration keys are defined by `ConfigKey`:

| Key | Purpose |
|---|---|
| `ConfigKey::AUTH` | Root authentication configuration. |
| `ConfigKey::STRATEGIES` | Ordered authentication strategies. |
| `ConfigKey::SESSION` | Session authentication and session manager options. |
| `ConfigKey::REMEMBER_ME` | Remember-me token options. |
| `ConfigKey::JWT` | JWT access/refresh token options. |
| `ConfigKey::MAGIC_LINK` | Magic-link request and verification options. |
| `ConfigKey::PASSWORD_RESET` | Password reset token options. |
| `ConfigKey::DENIED` | HTTP response factory for denied authentication. |
| `ConfigKey::LISTENERS` | Authentication event listeners. |

## Failure Model

Normal authentication failure is represented by `DeniedReasonInterface`, not an exception. Exceptions are reserved for infrastructure or programming errors: unsupported payloads, invalid payload extraction, storage failures, invalid token configuration, or transport failures.
