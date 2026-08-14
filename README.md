# Componenta Auth

Authentication contracts and PSR-7/PSR-15 building blocks for Componenta applications on PHP 8.4+.

The package supports password login, stateful sessions, remember-me credentials, signed JWT access tokens with stateful opaque refresh grants, OTP, magic links, password reset, and authentication lifecycle events.

## Requirements

- PHP 8.4+;
- `ext-ctype`, `ext-filter`, `ext-mbstring`;
- PSR-7, PSR-15, PSR-17 and PSR-20 implementations;
- Componenta DI 2 or 3;
- Cycle Database for built-in SQL stores.

## Canonical identity

Authentication uses `Componenta\Identity\IdentityInterface`. The identity UUID is the only public subject identifier:

```php
$subjectId = $identity->uuid;
```

Sessions, remember-me grants, one-time tokens, OTP challenges, refresh grants and JWT `sub` use this UUID. There is no auth-specific subject ID and no request-local mutable state on the identity object.

## Authenticator composition

Strategy order is explicit and security-sensitive:

```php
return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            CompensatingRememberMeStrategy::class,
            PasswordStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
        'rememberMe' => ['enabled' => true],
    ],
];
```

`AuthenticatorFactory` rejects empty lists, duplicates, missing/non-strategy services and use of remember-me strategies while remember-me is disabled. The raw built-in `RememberMeStrategy` is deliberately rejected in this middleware-oriented chain; configure `CompensatingRememberMeStrategy` so a successfully rotated remember bearer and session are revoked if their response-side replacement is later discarded. Direct callers that do not use `CredentialTransportState` may still use the raw strategy as a low-level primitive and own publication/rollback themselves.

A denial is **terminal by default**. A strategy may return `AuthenticationResult(..., continueOnFailure: true)` only for an intentional soft failure such as an invalid session credential when a remember-me credential from the same request may still authenticate the subject. Security denials such as rate limiting or disabled-account decisions therefore cannot be bypassed by a later strategy merely because it supports the same payload.

`AuthenticationResult` itself is fail-closed:

- a denied result cannot carry a session;
- a denied result cannot carry a response-side credential mutation;
- a successful result cannot request chain continuation;
- a returned session must belong to the returned identity.

## Request-scoped credential transport

`AuthenticationMiddleware` shares one `CredentialTransportState` through nested authentication layers. Each queued mutation retains its own `PayloadStorageInterface`, so different nested transports do not accidentally apply each other's payloads.

`clear()` is terminal. A logout clears every transport registered on the request and discards queued credential writes. If a successful authentication result needs a transport mutation but the middleware has no storage, it fails **before** invoking the downstream application handler.

Explicit password and OTP session login replace existing browser authentication state. The public magic-link session verifier requires `ReplacingPayloadStorage`, so direct construction cannot accidentally preserve or re-apply an older session/remember principal; the Componenta factory supplies this wrapper automatically.

The current authenticated session is attached to the PSR-7 request under `SessionInterface::class`; it is not stored on the identity.

`LogoutHandler` is designed to run **after `AuthenticationMiddleware`**. Server-side termination uses the authenticated `SessionInterface::class` request attribute. Invoking the logout handler standalone can remove the client-side credential, but it cannot safely infer which unauthenticated server-side session row should be terminated.

## Sessions

The built-in `DatabaseSessionManager`:

- validates idle and absolute expiry on the primary/write connection;
- throttles touch writes;
- performs regeneration transactionally with an optimistic claim;
- invalidates the presented old session ID immediately after successful regeneration;
- never resolves an old ID to its successor;
- serializes termination with regeneration and terminates any already-created replacement lineage;
- serializes subject-wide `terminateAll()` with regeneration so a concurrent rotation cannot escape global session termination;
- executes critical lifecycle participants inside the owning transaction and observers after commit;
- performs bounded cleanup with an expiry recheck before delete.

Session timestamps are normalized to UTC using the fixed internal format `Y-m-d H:i:s`; the representation is not a public configuration option.

The built-in session table is credential-bearing storage: live session IDs are recoverable because the public session-management API can enumerate sessions and the persistence model must track replacement lineage. Session DTO debug/JSON output redacts IDs, but applications must still restrict database/log access to the session table. Hashing the existing `id` column in place would not be compatible with the current enumeration/lineage contract and therefore is not presented as a drop-in hardening change.

## Remember-me

Remember-me is disabled by default. Enabling it automatically activates the critical termination and regeneration listeners required by the lifecycle.

The v2 remember-me model uses a **stable grant row with rotating bearer material**. It no longer deletes the grant before creating the successor credential.

`RememberMeTokenManagerInterface` exposes:

```php
create(UuidInterface $subjectId, string $sessionId): string;
rotate(string $plainToken): ?RememberMeRotation;
bindRotation(RememberMeRotation $rotation, string $newSessionId): bool;
```

The bearer rotation is single-winner. The grant tracks both the current `session_id` and `previous_session_id`; logout/revocation matches either value. This prevents a concurrent remember-me rotation from escaping a logout that targets the session from which the grant originated.

When remember-me runs inside `AuthenticationMiddleware`, use `CompensatingRememberMeStrategy`. It delegates authentication to the raw strategy but registers request-scoped compensation after a successful bind. If a later nested denial, UUID conflict, explicit login replacement, missing storage or downstream exception discards the queued replacement credential, the successor remember bearer is revoked and the unpublished session is terminated. A successfully applied response clears the compensation without revoking the delivered credential.

Minimum schema:

```text
remember_me_tokens
  id                   PRIMARY KEY
  user_id              NOT NULL, indexed
  token                UNIQUE NOT NULL   # SHA-256 representation
  session_id           NOT NULL, indexed
  previous_session_id  nullable, indexed
  expires_at           NOT NULL
  created_at           NOT NULL
```

Plain remember-me bearer values are never persisted.

## OTP

`OtpConfig` controls the actual protocol profile:

```php
'auth' => [
    'otp' => [
        'length' => 6,       // 6..18 digits
        'ttl' => 300,        // max 600 seconds
        'maxAttempts' => 5,
        'hmacKey' => $_ENV['AUTH_OTP_HMAC_KEY'], // >= 32 bytes
    ],
];
```

The extractor requires **exactly** the configured code length before the request reaches attempt accounting.

`DatabaseCodeStore` persists an HMAC-SHA-256 verifier instead of the numeric OTP and uses a random `challenge_id` as an optimistic version. Verification, failed-attempt accounting and consume are one challenge-version transition: a correct code racing the final failed attempt cannot authenticate after `maxAttempts` has already been reached.

Every negative public OTP verification **response** is deliberately collapsed to `invalid_code`. Internal store states such as expiry or attempt exhaustion are not serialized through the authentication response because doing so would create a direct account/challenge-existence oracle.

This is a public response-semantics guarantee, not a claim that different SQL states have identical end-to-end latency. A missing row and a failed-attempt CAS can require different database work. The package therefore does not add blocking sleeps or expensive dummy hashing, which would create a request-amplification/DoS primitive. Production `OtpRequestQueueInterface` adapters should be durable and non-inline when account-existence request timing matters, and verification/request endpoints still require application-level rate limiting.

`OtpRequest` contains one identity/destination value. The built-in processor cannot look up one identity and deliver the code to a different arbitrary destination. Applications needing alternative delivery routing must validate ownership in an application-specific adapter before enqueueing.

An application-level destination/account rate limiter is still required; `maxAttempts` limits one challenge only.

## One-time tokens: purpose separation

`TokenConfig` requires a machine-readable `purpose`, for example:

```php
new TokenConfig('magic_link_tokens', 'magic_link');
new TokenConfig('password_reset_tokens', 'password_reset');
```

The purpose is domain-separated into the stored token representation:

```text
SHA-256(purpose || NUL || bearer)
```

Therefore a magic-link token cannot be consumed by a password-reset manager even if an application accidentally points both managers at the same table.

`TokenRequest` contains the lookup/delivery identity, an explicit machine-readable `purpose`, and optional non-sensitive context; it does not accept a separate untrusted destination. Context keys are bounded machine-readable identifiers and context values are bounded to 4096 bytes and reject control characters before they can reach a queue adapter or URL-building sender. `TokenRequestQueueInterface` is a durable multi-purpose queue boundary: adapters must preserve and route on `purpose`, while a purpose-bound `TokenRequestProcessor` rejects misrouted work before provider lookup, token generation or delivery. Production adapters should not perform provider lookup or delivery inline when uniform account-existence request timing matters.

Magic-link verification responses set `Referrer-Policy: no-referrer`, including success and denial paths, so a URL-borne bearer is not propagated as a downstream referrer. Query-string credentials can still reach browser history and upstream reverse-proxy/access logs **before** application response headers are applied; deployments should redact query credentials from logs and avoid third-party resources on verification endpoints. The bearer remains one-time regardless of transport.

## JWT access and refresh tokens

JWT validation uses an explicit issuer/audience/type profile and checks signature, `iat`, optional `nbf`, `exp`, clock skew and maximum access-token lifetime. Registered claims cannot be replaced by custom claims. HMAC secrets must be at least 32/48/64 bytes for HS256/HS384/HS512.

Refresh grants use opaque 32-64 byte bearer IDs. The default `DatabaseRefreshTokenStore`:

- stores only SHA-256 token representations;
- serializes transitions through a durable family row;
- consumes the presented token and inserts its successor in one transaction;
- rolls back the presented-token claim if successor persistence fails;
- makes ordinary revocation terminal for the complete family and serializes it with rotation;
- keeps ordinary revocation distinct from replay compromise;
- on replay marks the family compromised and revokes all active descendants;
- reads security state from the primary/write connection.

`DatabaseRefreshTokenHousekeeper::cleanup($now, $limit)` performs bounded housekeeping in two stages. It first prunes at most `$limit` token-history rows whose own bearer expiry has passed, including expired history belonging to a still-live sliding family; each deletion serializes through that family row. It then considers at most `$limit` terminal family candidates and deletes a family only after its history has drained and expiry is rechecked on the primary under the same serialization point. Cleanup therefore cannot delete a concurrently created active successor.

Token responses use `Cache-Control: no-store` and `Pragma: no-cache`. Semantically empty token responses explicitly remove `Content-Type`; response semantics never depend on PSR-7 stream size, which may legitimately be unknown.

## Password reset

`PasswordResetServiceInterface` owns the complete account-recovery transition. `PasswordResetResult::Success` means the reset token was accepted and consumed, the password changed, and pre-reset session, remember-me and refresh credentials were durably or logically invalidated. Password policy belongs to the service and can return `PasswordRejected`.

The package cannot manufacture a transaction across an application-owned password repository and unrelated external stores. Implementations spanning resources must use an equivalent credential-version/outbox/idempotent model and must never return `Success` after a partial transition.

## Events and clocks

Listeners use one extensible property-oriented contract:

```php
interface EventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events { get; }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void;
}
```

The old per-event marker interfaces and `ListenerFactory` are removed. `CriticalEventListenerInterface` remains because it has independent failure semantics.

Event DTOs do not create clocks. Their timestamp is mandatory and is supplied by the service that owns the transition. Generic authentication/logout events are best-effort observers; security-critical session lifecycle listeners participate in the owning transition where applicable. Best-effort session-GC scheduling likewise isolates scheduler, random-source and logger failures from an already successful application response.

Componenta factories also honor the shared PSR-20 `ClockInterface` for event timestamps, JWT access/refresh issuance/validation and logout observer time. Constructor defaults remain only as a direct-construction fallback for non-Componenta containers.

Credential-bearing DTOs and audit containers use redacted debug/JSON representations. Generic authentication events contain payload type/subject UUID metadata, never raw credentials. Package-owned exception-prone boundaries redact credential-bearing request/context/storage/event/session arguments, generated credential helper values, and DI container objects that may carry configuration secrets. PHP parameter attributes are not inherited by concrete implementations, so custom strategies, stores, listeners, senders and factories must apply equivalent `#[SensitiveParameter]` annotations on their own credential/config-bearing frames. Third-party implementations remain responsible for their own stack frames, and applications should not expose exception traces to untrusted clients.

## Denial responses and malformed input

`DeniedReasonInterface::$attributes` is internal audit context. The built-in `DeniedResponseFactory` publishes only the stable error code. Applications needing a richer public body must replace `DeniedResponseFactoryInterface`; there is no `PublicDeniedReasonInterface` capability.

Strict extractors throw `InvalidPayloadException`. Built-in handlers should run behind `InvalidPayloadMiddleware` (or an equivalent application mapper) to produce a stable 400 response.

Cookie-authenticated state-changing endpoints, including logout where appropriate to the application, remain subject to the application's CSRF policy. The auth package cannot infer trusted origins or deployment topology.

## Database consistency

Authentication-state reads in the built-in session, remember-me, one-time, refresh and OTP stores are pinned to the Cycle `WRITE` driver. A lagging read replica must never resurrect revoked credentials.

The repository release gate runs SQLite tests and real MySQL 8.4/InnoDB integration. Separate `pcntl` concurrency gates start independent processes/connections and prove:

- concurrent refresh rotation results in one rotation plus replay compromise and leaves zero active descendants;
- concurrent refresh rotation versus ordinary revocation leaves the family revoked, uncompromised, and with zero active successors;
- concurrent refresh rotation versus housekeeping either preserves the newly rotated family or makes the later rotation fail closed after cleanup wins;
- concurrent verification of one OTP is single-winner;
- a correct OTP racing the final wrong attempt cannot authenticate after the challenge has reached `maxAttempts`;
- concurrent remember-me rotation and logout cannot leave a descendant grant;
- concurrent session regeneration and logout cannot leave an active replacement session;
- concurrent session regeneration and `terminateAll(subject)` cannot leave any session for that subject, regardless of which transition linearizes first.

## Verification

Every supported matrix job runs:

```text
PHP 8.4 / DI 2.x
PHP 8.4 / DI 3.x
PHP 8.5 / DI 2.x
PHP 8.5 / DI 3.x
```

and executes syntax checks, PHPUnit, PHPStan level max, Composer audit, MySQL 8.4 integration, the real concurrency gates and repository invariants from `tools/verify.sh`.

Third-party GitHub Actions are pinned to immutable 40-character commit SHAs. `tools/verify.sh` rejects floating action refs so a future tag move cannot silently change the release gate.

See [MIGRATION-v2.md](MIGRATION-v2.md) for breaking changes and [QUALITY-GATES.md](QUALITY-GATES.md) for release invariants.
