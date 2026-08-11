# Migrating to componenta/auth v2

Version 2 intentionally changes storage, identity, composition and property contracts. The former APIs could not enforce credential-lifecycle invariants under concurrency, partial failure and long-running workers.

## Canonical identity UUID

Removed:

```text
Componenta\Auth\AuthSubjectInterface
Componenta\Auth\AuthSubject
```

Use the UUID already provided by `IdentityInterface`:

```php
$subjectId = $identity->uuid->toString();
```

Update application stores so sessions, remember-me tokens, one-time tokens, OTP challenges, refresh grants and JWT `sub` use that same UUID. Public v2 ownership contracts accept `UuidInterface`; internal database IDs belong inside persistence adapters.

## Request-local session state

`SessionAwareInterface` remains the capability for exposing all sessions owned by an identity:

```php
interface SessionAwareInterface
{
    public SessionCollectionInterface $sessions { get; }
}
```

Only the mutable request-local `currentSessionId` property has been removed. Do not add it back to the identity entity. `AuthenticationResult` now has:

```php
public ?SessionInterface $session;
```

`AuthenticationMiddleware` attaches it to the PSR-7 request under `SessionInterface::class`.

The generic `AuthenticationResult::$attributes` bag has been removed. Client code obtains the current request session from the PSR-7 attribute `SessionInterface::class`; `$identity->sessions` remains the collection of all sessions belonging to that identity.

## Property API

Replace these calls:

```text
ContextInterface::getAttributes()       -> $context->attributes
SessionInterface::getAttributes()       -> $session->attributes
SessionCollectionInterface::isEmpty()   -> $sessions->empty
CredentialTransportState::isEmpty()     -> $state->empty
CredentialTransportState::shouldClear() -> $state->cleared
CredentialTransportState::payloads()    -> $state->payloads
RefreshToken::isRevoked()               -> $token->revoked
PublicDeniedReasonInterface::publicDetails() -> $reason->publicDetails
```

Methods that accept input or perform actions are unchanged in style.

## Password providers

The password provider no longer receives a credential-bearing payload:

```php
interface UserProviderInterface
{
    public function findByIdentity(
        string $identity,
    ): null|(IdentityInterface&PasswordAwareInterface);
}
```

Update providers that previously implemented `provide(Payload $payload)`.

## Shared authenticator for verification handlers

`LoginHandler`, OTP `VerifyHandler` and magic-link `VerifyHandler` now depend on `AuthenticatorInterface`, not an individual strategy. Ensure every strategy used by those handlers appears in ordered `auth.strategies`.

## Delivery queues

Removed zero-logic wrappers and unused magic-link denial types:

```text
Componenta\Auth\Token\TokenRequester
Componenta\Auth\Http\Strategy\Otp\OtpRequester
Componenta\Auth\Http\Strategy\MagicLink\Denied\TokenAlreadyUsed
Componenta\Auth\Http\Strategy\MagicLink\Denied\TokenExpired
```

Magic-link verification has always collapsed negative outcomes to `InvalidToken`; the two removed denial classes had no execution path.

Inject `TokenRequestQueueInterface` or `OtpRequestQueueInterface` directly and enqueue `TokenRequest`/`OtpRequest`.

Default factory service IDs for application queues:

```text
auth.magicLink.queue
auth.passwordReset.queue
```

OTP request handling resolves `OtpRequestQueueInterface::class`.

## Ordered authenticator composition

Define every active strategy explicitly:

```php
'auth' => [
    'strategies' => [
        SessionStrategy::class,
        RememberMeStrategy::class,
        PasswordStrategy::class,
        OtpStrategy::class,
        MagicLinkStrategy::class,
        JwtStrategy::class,
    ],
    'events' => true,
],
```

Empty, duplicate, missing and non-strategy services fail fast.

## JWT profile

`JwtConfig` now requires explicit issuer and audience:

```php
new JwtConfig(
    issuer: 'https://issuer.example',
    audience: 'componenta-api',
    type: 'at+jwt',
    accessTtl: 900,
    refreshTtl: 604800,
    clockSkew: 30,
);
```

The DI config must define non-empty `auth.jwt.issuer` and `auth.jwt.audience` before resolving JWT services. Tokens without the exact issuer, audience and type are rejected.

HMAC secrets must meet the digest-size minimum for the selected algorithm.

`RefreshTokenGenerator` accepts 32–64 bytes only. Test fixtures that used short generators must be updated.

## Refresh store

Implement the atomic store contract:

- `storeInitial()` persists the first family member;
- `rotateAtomically()` serializes validation, revocation, replay compromise and successor creation;
- `revokeAllForSubject()` supports account recovery.

A `Rotated` result must return the exact successor ID and expiry supplied to `rotateAtomically()`, an active token, a valid family ID and a non-empty subject ID.

## OTP store

Replace separate lookup/attempt/consume operations with `verifyAndConsume()`. The operation must use one locked or versioned challenge record. Return `Expired` when expiry is known; it is no longer collapsed into `Invalid` inside the strategy.

## Password reset

Register `PasswordResetServiceInterface`. The service receives the plaintext reset token and new password, validates/locks the token before expensive hashing, and owns the complete security transition. `PasswordResetResult::Success` means: reset token consumed, password changed, and old session, remember-me and refresh credentials invalidated.

`PasswordUpdaterInterface` has been removed because the HTTP handler no longer orchestrates the security transition itself.

## Session and transport lifecycle

- Nested authentication/session middleware layers reuse one request-scoped `CredentialTransportState`; only its owner applies the final mutation.
- A new authentication result removes stale identity, denial and session request attributes before installing the current result.
- `LogoutHandler` no longer performs a duplicate cookie removal when `AuthenticationMiddleware` owns terminal transport commit.
- Custom authentication middleware must attach the verified `SessionInterface` if logout should terminate that server-side session.
- Session touch rechecks idle/absolute expiry.
- Session cleanup is bounded and rechecks expiry before delete.
- `SessionCollection::pluck()` rejects unknown keys.

## One-time token storage

`TokenManagerInterface::replaceForSubject()` replaces a subject challenge atomically. The built-in SQL manager uses an UPSERT, so the persistence schema must enforce a `UNIQUE` constraint on the canonical subject UUID column. Do not emulate replacement as independent `DELETE` and `INSERT` statements.

## Remember-me feature flag

Remember-me is disabled by default. Set `auth.rememberMe.enabled=true` only when `RememberMeTokenManagerInterface` is configured. Enabling the feature automatically adds the built-in termination and regeneration listeners; custom listener lists are deduplicated.

## Housekeeping signatures

The following methods are now bounded and return affected rows:

```php
SessionManagerInterface::cleanup(int $limit = 1000): int;
RememberMeTokenManagerInterface::cleanup(int $limit = 1000): int;
TokenManagerInterface::cleanup(int $limit = 1000): int;
```

Invoke them from a worker, cron task or scheduler.

## Composer requirements

The package now declares its direct PSR-17 and PSR-15 handler dependencies:

```text
psr/http-factory
psr/http-server-handler
```

`ext-mbstring` remains required.

## Removed dead API

The following unused/redundant symbols are removed in v2:

```text
AuthSubjectInterface
AuthSubject
RememberMeAwareInterface
PasswordUpdaterInterface
TokenRequester
OtpRequester
ConfigKey::COOKIE
ConfigKey::MAGIC_LINK
ConfigKey::PASSWORD_RESET
```

## Secure rollout order

1. Update identity/provider and storage adapters.
2. Deploy atomic refresh and OTP store implementations.
3. Register delivery queues and processors.
4. Configure ordered strategies and explicit JWT profile.
5. Deploy handlers and property-API consumers.
6. Run concurrency, DB integration, PHPUnit and PHPStan gates before production rollout.
