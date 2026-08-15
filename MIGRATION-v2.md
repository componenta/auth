# Migrating to componenta/auth v2

Version 2 intentionally breaks identity, credential-lifecycle, persistence and event APIs to make security invariants explicit.

## Identity and request state

Removed:

```text
AuthSubjectInterface
AuthSubject
RememberMeAwareInterface
```

`SessionAwareInterface` remains available for identities that expose their active sessions. Its v2 contract contains only the get-only `SessionCollectionInterface $sessions` property; remove `currentSessionId` from implementations. Session `UserProviderInterface` returns `IdentityInterface&SessionAwareInterface`, preserving this capability for session-authenticated identities.

Use `IdentityInterface::$uuid` as the only subject identifier. Obtain the current request session from `SessionInterface::class` on the PSR-7 request. Query all sessions through `SessionAwareInterface::$sessions` when the identity provides that capability, or explicitly through `SessionManagerInterface::all($identity->uuid)`.

Do not store `currentSessionId` or request-local authentication state on reusable identity objects.

## Identity normalization

`PasswordExtractor` no longer trims or lowercases identity input and no longer exposes `normalizeIdentity`. It now follows the same transport contract as recovery, magic-link and OTP request handlers: accept one bounded, control-character-free identity string and reject leading/trailing whitespace.

Case folding, Unicode/email canonicalization and aliases belong to the application/provider because the auth package cannot know whether an identity is an email address, a case-sensitive username or another identifier. Providers that previously relied on `PasswordExtractor` normalization must normalize consistently inside `findByIdentity()` (or before invoking the auth component) for every authentication and recovery flow.

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
$state->onDiscard($callback);
$state->discardQueued();
$state->apply($request, $response);
```

Nested middleware may use different storages. Terminal clear removes every registered transport and discards pending writes. `onDiscard()` registers compensation for server-side credential state that has been created but not yet published to the client; `discardQueued()` executes those pending compensations when a later authentication layer makes the queued credential unusable.

A middleware producing a successful credential mutation must have a `PayloadStorageInterface` before downstream application code runs.

## Remember-me migration

RememberMeToken and delete-on-consume semantics are removed. The manager now
uses a stable selector and rotating validator:

    create(UuidInterface $subjectId, string $sessionId): string;
    rotate(string $plainToken):
        RememberMeRotation|RememberMeCompromise|null;
    bindRotation(RememberMeRotation $rotation, string $newSessionId): bool;

Replaying a superseded validator deletes the grant and returns a compromise
signal; the strategy terminates its session lineage. Revocation uses the stable
selector, so an original bearer can still revoke its rotated successor.

Replace the old hash with a 32-character selector, add a 64-character verifier,
and revoke all existing remember-me grants because bearers cannot be migrated:

    ALTER TABLE remember_me_tokens
      MODIFY token CHAR(32) NOT NULL,
      ADD verifier CHAR(64) NOT NULL,
      MODIFY session_id VARBINARY(512) NOT NULL,
      ADD previous_session_id VARBINARY(512) NULL;

Deploy the manager, schema, CompensatingRememberMeStrategy and lifecycle
listeners together.
## Built-in SQL schema contract

The built-in SQL stores now ship a canonical MySQL 8.4/InnoDB schema at `resources/schema/mysql-8.4.sql`. Table and column names remain configurable, but PK/UNIQUE/FK constraints, compatible widths, binary comparison semantics for credential keys, and cleanup indexes are part of the store contract rather than optional tuning.

Existing installations should review `resources/schema/README.md` before deploying the hardened stores. In particular, refresh families need an indexed family-level `expires_at` retention deadline, `family_id` must support the full 64-128 hexadecimal characters accepted by the refresh generator, and case-sensitive session/OTP keys must not be silently folded by a case-insensitive database collation.

## OTP

`OtpConfig` is a DI/config service. `OtpExtractor` now requires it and accepts exactly `OtpConfig::$length` digits.

All negative authentication results are public `invalid_code`; store-level `Expired` and `TooManyAttempts` remain internal. Applications must not restore distinct public errors unless they accept the resulting account-enumeration oracle.

`OtpRequest` no longer accepts a separate destination. The built-in flow uses the same identity for provider lookup, challenge key and delivery destination. Custom delivery routing belongs in an application adapter that verifies ownership.

`DatabaseCodeStore` now treats successful consume and failed-attempt accounting as one challenge-version transition. Custom `CodeStoreInterface` implementations must ensure a correct code racing the final failed attempt cannot authenticate after `maxAttempts` has already been reached.

`CodeStoreInterface` additionally exposes bounded retention cleanup:

```php
cleanup(int $now, int $limit = 1000): int;
```

Custom stores must recheck expiry before destructive deletion. Queue workers must also preserve enqueue order for the same identity: the built-in model intentionally keeps one current OTP challenge per destination, so out-of-order parallel delivery could otherwise send an already-superseded code last.

## One-time token purpose

`TokenConfig` now requires `purpose`:

```php
new TokenConfig('magic_link_tokens', 'magic_link');
```

The stored token hash is domain-separated by purpose. Managers for different flows therefore cannot consume each other's bearer tokens, even when a table is accidentally shared.

`TokenRequest` no longer accepts a separate destination and now requires an explicit purpose:

```php
new TokenRequest(
    identity: $identity,
    purpose: TokenRequest::PURPOSE_MAGIC_LINK,
);
```

Magic-link requests enqueue `magic_link`; forgot-password requests enqueue `password_reset`. Queue adapters serving multiple one-time-token flows must preserve and route on `TokenRequest::$purpose`. Construct each `TokenRequestProcessor` with its expected purpose; it rejects misrouted work before provider lookup, token generation or delivery. Workers must serialize the same `(purpose, identity)` key in enqueue order because each purpose-specific built-in store keeps one current token per subject.

The public `MagicLink\VerifyHandler` now requires `ReplacingPayloadStorage`. This is a constructor-level security contract: successful magic-link verification must discard the previous browser principal before storing the new session credential. Custom/manual construction must wrap the underlying storage in
ReplacingPayloadStorage; a generic PayloadStorageInterface is insufficient.

The consuming session and JWT magic-link endpoints accept only POST with token
in the parsed body. Route mail links to a non-consuming confirmation page and
submit the token by POST. GET returns 405 without consuming the bearer.

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

`RefreshTokenStoreInterface` now has an additional primary-read preflight:

```php
findActiveSubject(string $tokenId, int $now): ?UuidInterface;
```

It is deliberately non-authoritative. It allows provider lookup, access-token signing and response allocation to fail before the presented refresh bearer is irreversibly rotated; `rotateAtomically()` remains the final serialized authorization decision and must repeat every state check. Custom stores must preserve that distinction.

`DatabaseRefreshTokenHousekeeper::cleanup($now, $limit)` uses indexed `refresh_tokens.expires_at` to prune expired token-history rows in a bounded batch, including history belonging to a still-live sliding family. Each history deletion serializes through the family row. It then selects terminal family candidates from indexed `refresh_token_families.expires_at`; final family deletion uses the same serialization point and occurs only after the bounded history drain has left the family with no token rows.

Replay detection therefore applies only while the presented bearer itself is unexpired. Reuse of a consumed bearer before its `expires_at` still compromises the complete family. Once that bearer has expired, it may be removed by housekeeping and a later presentation is merely expired/invalid; it must not compromise a live successor family. Schedule housekeeping regularly and retain the canonical expiry indexes, including `idx_refresh_token_expiry`.

Custom `RefreshTokenStoreInterface` implementations must provide equivalent family serialization, successor rollback, replay-compromise semantics for unexpired bearers, primary-read preflight, and bounded safe retention cleanup.

## JWT bearer size contract

The package now uses one shared bearer syntax/size contract for `BearerExtractor`, `BearerPayload`, built-in HMAC/RSA signers and built-in token responses. A signer must not emit an access token that the standard HTTP bearer transport would reject; custom signers used with built-in token handlers are checked before any refresh credential is issued or rotated.

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

The following dead APIs were removed:

```text
AuthSubject / AuthSubjectInterface
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

1. Upgrade identity ownership to canonical UUID contracts and move identity normalization into providers/application policy.
2. Apply the canonical SQL-store migration requirements in `resources/schema/README.md`, including remember-me lineage, binary credential-key comparison, cleanup indexes and refresh family retention state.
3. Configure OTP HMAC secret/profile and update custom `CodeStoreInterface` implementations for bounded cleanup.
4. Assign a distinct one-time-token `purpose` to every flow and preserve `TokenRequest::$purpose` through queue routing/workers; serialize issuance workers per identity/purpose key, and construct magic-link verification with `ReplacingPayloadStorage`.
5. Update custom `RefreshTokenStoreInterface` implementations for primary preflight, bounded expired-history pruning and family-level retention cleanup.
6. Deploy primary-pinned credential stores and lifecycle listeners together; use `CompensatingRememberMeStrategy` in middleware chains.
7. Update custom event listeners to `$events` property subscriptions and pass timestamps explicitly when creating events.
8. Keep strict handlers behind `InvalidPayloadMiddleware` or an equivalent 400 mapper.
9. Run the repository's MySQL concurrency tests against the deployment database/dialect.
10. Verify application-owned `PasswordResetServiceInterface`, queues, CSRF policy and account/endpoint rate limits independently.
