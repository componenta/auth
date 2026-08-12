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
            RememberMeStrategy::class,
            PasswordStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
        'rememberMe' => ['enabled' => true],
    ],
];
```

`AuthenticatorFactory` rejects empty lists, duplicates, missing/non-strategy services and use of the built-in `RememberMeStrategy` while remember-me is disabled.

A denial is **terminal by default**. A strategy may return `AuthenticationResult(..., continueOnFailure: true)` only for an intentional soft failure such as an invalid session credential when a remember-me credential from the same request may still authenticate the subject. Security denials such as rate limiting or disabled-account decisions therefore cannot be bypassed by a later strategy merely because it supports the same payload.

`AuthenticationResult` itself is fail-closed:

- a denied result cannot carry a session;
- a denied result cannot carry a response-side credential mutation;
- a successful result cannot request chain continuation;
- a returned session must belong to the returned identity.

## Request-scoped credential transport

`AuthenticationMiddleware` shares one `CredentialTransportState` through nested authentication layers. Each queued mutation retains its own `PayloadStorageInterface`, so different nested transports do not accidentally apply each other's payloads.

`clear()` is terminal. A logout clears every transport registered on the request and discards queued credential writes. If a successful authentication result needs a transport mutation but the middleware has no storage, it fails **before** invoking the downstream application handler.

The current authenticated session is attached to the PSR-7 request under `SessionInterface::class`; it is not stored on the identity.

## Sessions

The built-in `DatabaseSessionManager`:

- validates idle and absolute expiry on the primary/write connection;
- throttles touch writes;
- performs regeneration transactionally with an optimistic claim;
- invalidates the presented old session ID immediately after successful regeneration;
- never resolves an old ID to its successor;
- executes critical lifecycle participants inside the owning transaction and observers after commit;
- performs bounded cleanup with an expiry recheck before delete.

Session timestamps are normalized to UTC using the fixed internal format `Y-m-d H:i:s`; the representation is not a public configuration option.

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

`DatabaseCodeStore` persists an HMAC-SHA-256 verifier instead of the numeric OTP and uses a random `challenge_id` as an optimistic version. Verification, failed-attempt accounting and consume are single-winner operations over that challenge version.

Every negative public OTP verification outcome is deliberately collapsed to `invalid_code`. Internal store states such as expiry or attempt exhaustion are not exposed through the authentication response because doing so would let a caller distinguish destinations for which a worker created a challenge from destinations for which no account exists.

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

`TokenRequest` also contains only the lookup/delivery identity plus non-sensitive context; the built-in processor does not accept a separate untrusted destination.

## JWT access and refresh tokens

JWT validation uses an explicit issuer/audience/type profile and checks signature, `iat`, optional `nbf`, `exp`, clock skew and maximum access-token lifetime. Registered claims cannot be replaced by custom claims. HMAC secrets must be at least 32/48/64 bytes for HS256/HS384/HS512.

Refresh grants use opaque 32-64 byte bearer IDs. The default `DatabaseRefreshTokenStore`:

- stores only SHA-256 token representations;
- serializes transitions through a durable family row;
- consumes the presented token and inserts its successor in one transaction;
- rolls back the presented-token claim if successor persistence fails;
- distinguishes ordinary family revocation from replay compromise;
- on replay marks the family compromised and revokes all active descendants;
- reads security state from the primary/write connection.

`DatabaseRefreshTokenHousekeeper::cleanup($now, $limit)` provides bounded housekeeping. It deletes only families for which the complete token history has expired, rechecks the candidate families on the primary and preserves any history that can still participate in replay detection.

Token responses use `Cache-Control: no-store` and `Pragma: no-cache`.

## Password reset

`PasswordResetServiceInterface` owns the complete account-recovery transition. `PasswordResetResult::Success` means the reset token was accepted and consumed, the password changed, and pre-reset session, remember-me and refresh credentials were durably or logically invalidated. Password policy belongs to the service and can return `PasswordRejected`.

The package cannot manufacture a transaction across an application-owned password repository and unrelated external stores. Implementations spanning resources must use an equivalent credential-version/outbox/idempotent model and must never return `Success` after a partial transition.

## Events

Listeners use one extensible property-oriented contract:

```php
interface EventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events { get; }

    public function handleEvent(EventInterface $event): void;
}
```

The old per-event marker interfaces and `ListenerFactory` are removed. `CriticalEventListenerInterface` remains because it has independent failure semantics.

Event DTOs do not create clocks. Their timestamp is mandatory and is supplied by the service that owns the transition. Generic authentication/logout events are best-effort observers; security-critical session lifecycle listeners participate in the owning transition where applicable.

Credential-bearing DTOs and audit containers use redacted debug/JSON representations. Generic authentication events contain payload type/subject UUID metadata, never raw credentials.

## Denial responses and malformed input

`DeniedReasonInterface::$attributes` is internal audit context. The built-in `DeniedResponseFactory` publishes only the stable error code. Applications needing a richer public body must replace `DeniedResponseFactoryInterface`; there is no `PublicDeniedReasonInterface` capability.

Strict extractors throw `InvalidPayloadException`. Built-in handlers should run behind `InvalidPayloadMiddleware` (or an equivalent application mapper) to produce a stable 400 response.

## Database consistency

Authentication-state reads in the built-in session, remember-me, one-time, refresh and OTP stores are pinned to the Cycle `WRITE` driver. A lagging read replica must never resurrect revoked credentials.

The repository release gate runs SQLite tests and real MySQL 8.4/InnoDB integration. A separate `pcntl` concurrency gate starts independent processes/connections and proves:

- concurrent refresh rotation results in one rotation plus replay compromise and leaves zero active descendants;
- concurrent verification of one OTP is single-winner;
- concurrent remember-me rotation and logout cannot leave a descendant grant.

## Verification

Every supported matrix job runs:

```text
PHP 8.4 / DI 2.x
PHP 8.4 / DI 3.x
PHP 8.5 / DI 2.x
PHP 8.5 / DI 3.x
```

and executes syntax checks, PHPUnit, PHPStan level max, Composer audit, MySQL 8.4 integration, the real concurrency gate and repository invariants from `tools/verify.sh`.

See [MIGRATION-v2.md](MIGRATION-v2.md) for breaking changes and [QUALITY-GATES.md](QUALITY-GATES.md) for release invariants.
