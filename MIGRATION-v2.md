# Migrating to componenta/auth v2

Version 2 intentionally breaks identity, credential-lifecycle, persistence and event APIs to make security invariants explicit.

## Identity and request state

Removed:

```text
AuthSubjectInterface
AuthSubject
SessionAwareInterface
RememberMeAwareInterface
```

Use `IdentityInterface::$uuid` as the only subject identifier. Obtain the current request session from `SessionInterface::class` on the PSR-7 request and query all sessions explicitly through `SessionManagerInterface::all($identity->uuid)`.

Do not store `currentSessionId` or request-local authentication state on reusable identity objects.

## AuthenticationResult and strategy chaining

A denial is terminal unless the strategy explicitly marks it as a soft failure:

```php
new AuthenticationResult(
    subject: new InvalidCredentials(),
    continueOnFailure: true,
);
```

Use this only when another configured strategy is intentionally allowed to handle the same request state. A denied result cannot contain a session or transport mutation. A successful result cannot set `continueOnFailure`.

Custom strategies that previously relied on the old "every denial continues" behavior must choose their terminal/soft semantics explicitly.

## Credential transport

`CredentialTransportState` now records the storage associated with each queued payload. Its action API is:

```php
$state->register($storage);
$state->queue($storage, $payload);
$state->clear($storage);
$state->apply($request, $response);
```

Nested middleware may use different storages. Terminal clear removes every registered transport and discards pending writes.

A middleware producing a successful credential mutation must have a `PayloadStorageInterface` before downstream application code runs.

## Remember-me migration

`RememberMeToken` and delete-on-consume semantics are removed. `RememberMeTokenManagerInterface` now exposes bearer rotation plus a separate session-binding check:

```php
create(UuidInterface $subjectId, string $sessionId): string;
rotate(string $plainToken): ?RememberMeRotation;
bindRotation(RememberMeRotation $rotation, string $newSessionId): bool;
```

`sessionId` is no longer nullable.

Add the lineage column and indexes before deploying the new manager:

```sql
ALTER TABLE remember_me_tokens
  MODIFY session_id VARCHAR(512) NOT NULL,
  ADD previous_session_id VARCHAR(512) NULL,
  ADD INDEX idx_remember_session (session_id),
  ADD INDEX idx_remember_previous_session (previous_session_id);
```

Exact types should match your schema. The security property is that revocation can match both the current and immediately previous session ID while bearer rotation/session binding is in flight.

Deploy the new manager, strategy and lifecycle listeners together. Do not mix the old delete-on-consume manager with the new strategy.

## OTP

`OtpConfig` is a DI/config service. `OtpExtractor` now requires it and accepts exactly `OtpConfig::$length` digits.

All negative authentication results are public `invalid_code`; store-level `Expired` and `TooManyAttempts` remain internal. Applications must not restore distinct public errors unless they accept the resulting account-enumeration oracle.

`OtpRequest` no longer accepts a separate destination. The built-in flow uses the same identity for provider lookup, challenge key and delivery destination. Custom delivery routing belongs in an application adapter that verifies ownership.

## One-time token purpose

`TokenConfig` now requires `purpose`:

```php
new TokenConfig('magic_link_tokens', 'magic_link');
```

The stored token hash is domain-separated by purpose. Managers for different flows therefore cannot consume each other's bearer tokens, even when a table is accidentally shared.

`TokenRequest` also no longer accepts a separate destination.

## Events

Removed event-specific listener markers:

```text
AuthenticationAttemptedListenerInterface
AuthenticationSucceededListenerInterface
AuthenticationDeniedListenerInterface
LoggedOutListenerInterface
SessionRegeneratedListenerInterface
SessionsTerminatedListenerInterface
AllSessionsTerminatedListenerInterface
ListenerFactory
```

Implement one contract instead:

```php
interface EventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events { get; }

    public function handleEvent(EventInterface $event): void;
}
```

`CriticalEventListenerInterface` remains for synchronous security participants.

All event constructors now require an explicit `DateTimeImmutable $timestamp`. Pass time from the service's injected clock; event DTOs no longer instantiate clocks internally.

## Database timestamps

`dateFormat` is no longer a public constructor/config option for session, remember-me or one-time-token stores. Built-in DATETIME persistence always uses UTC with `Y-m-d H:i:s`.

Remove obsolete `auth.session.dateFormat` and `auth.rememberMe.dateFormat` application configuration.

## Refresh grants

The built-in `DatabaseRefreshTokenStore` remains the default secure implementation of atomic rotation/replay handling.

Use `DatabaseRefreshTokenHousekeeper::cleanup($now, $limit)` for bounded retention cleanup. It deletes only families whose complete token history has expired; do not delete consumed members of still-relevant families because they are replay-detection history.

Custom `RefreshTokenStoreInterface` implementations must provide equivalent family serialization, successor rollback and replay-compromise semantics.

## Denial responses

`PublicDeniedReasonInterface` is removed. `DeniedReasonInterface::$attributes` is internal audit context only. Built-in `DeniedResponseFactory` emits only the stable code. Replace `DeniedResponseFactoryInterface` if the application deliberately wants a richer public schema.

## Packaging

Direct platform requirements now include:

```text
ext-ctype
ext-filter
ext-mbstring
```

## Removed dead API

The quality gate prevents reintroduction of:

```text
AuthSubject / AuthSubjectInterface
SessionAwareInterface
RememberMeAwareInterface
RememberMeToken
PasswordUpdaterInterface
TokenRequester
OtpRequester
PublicDeniedReasonInterface
old magic-link denial classes
event-specific listener marker interfaces
ListenerFactory
```

## Production rollout

1. Upgrade identity ownership to canonical UUID contracts.
2. Apply remember-me `previous_session_id` migration and make `session_id` non-null.
3. Configure OTP HMAC secret/profile and update extractors to receive `OtpConfig`.
4. Assign a distinct one-time-token `purpose` to every flow.
5. Deploy primary-pinned credential stores and lifecycle listeners together.
6. Update custom event listeners to `$events` property subscriptions and pass timestamps explicitly when creating events.
7. Keep strict handlers behind `InvalidPayloadMiddleware` or an equivalent 400 mapper.
8. Run the repository's MySQL concurrency tests against the deployment database/dialect.
9. Verify application-owned `PasswordResetServiceInterface`, queues, CSRF policy and account/endpoint rate limits independently.
