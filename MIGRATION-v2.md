# Migrating to componenta/auth v2

Version 2 intentionally changes identity, credential storage, session lifecycle, recovery and composition contracts. These changes remove races and ambiguous ownership that could not be fixed while preserving the v1 API.

## Canonical identity UUID

Removed:

```text
Componenta\Auth\AuthSubjectInterface
Componenta\Auth\AuthSubject
```

Use the UUID already provided by `IdentityInterface`:

```php
$subjectId = $identity->uuid;
$subject = $identity->uuid->toString();
```

Sessions, remember-me credentials, one-time tokens, OTP challenges, refresh grants and JWT `sub` all use that same identity UUID. Public ownership contracts accept `UuidInterface`; internal numeric database keys belong inside persistence adapters.

Every UUID-based user provider is now a security boundary: an implementation of `findByUuid($uuid)` must return either `null` or an identity whose `$identity->uuid` equals the requested UUID. Built-in authentication flows reject provider substitution instead of authenticating a different subject.

## Request-local session state

`SessionAwareInterface` has been removed. An identity is no longer required to expose persistence-backed session state.

Use `SessionManagerInterface` explicitly when an application needs all sessions for an identity:

```php
$sessions = $sessionManager->all($identity->uuid);
```

The session that authenticated the current request is request-scoped. `AuthenticationResult` exposes:

```php
public ?SessionInterface $session;
```

`AuthenticationMiddleware` attaches that session to the PSR-7 request under `SessionInterface::class`. Do not store a mutable `currentSessionId`, a session collection, or other request-local authentication state on reusable ORM/singleton identity objects.

The former generic `AuthenticationResult::$attributes` bag is removed.

## PHP 8.4 property API

State contracts use properties where no input/action is involved. Replace these calls:

```text
ContextInterface::getAttributes()       -> $context->attributes
SessionInterface::getAttributes()       -> $session->attributes
SessionCollectionInterface::isEmpty()   -> $sessions->empty
CredentialTransportState::isEmpty()     -> $state->empty
CredentialTransportState::shouldClear() -> $state->cleared
CredentialTransportState::payloads()    -> $state->payloads
RefreshToken::isRevoked()               -> $token->revoked
```

Methods remain methods when they accept input or perform an action, for example `getAttribute($name)`, `find($id)`, `consume($token)`, `queue()` and `clear()`.

## Denial response boundary

`PublicDeniedReasonInterface` and the `publicDetails` capability have been removed.

`DeniedReasonInterface::$attributes` is trusted audit context only. The built-in `DeniedResponseFactory` serializes only the validated denial `code`:

```json
{"error":"invalid_credentials"}
```

If an application intentionally needs additional client-facing denial fields, replace `DeniedResponseFactoryInterface` with an application-owned implementation. Do not reuse audit attributes as an implicit wire format.

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

The submitted password remains inside the authentication verifier and is not passed to the application provider.

## Shared authenticator for verification handlers

Password login, OTP verification and magic-link verification depend on the configured `AuthenticatorInterface`, not an individual strategy. Every active strategy therefore has to appear in the ordered `auth.strategies` list.

Empty, duplicate, missing and non-strategy entries fail fast. `RememberMeStrategy` additionally requires `auth.rememberMe.enabled=true`.

## Delivery queues

Removed zero-logic wrappers and unreachable magic-link denial types:

```text
Componenta\Auth\Token\TokenRequester
Componenta\Auth\Http\Strategy\Otp\OtpRequester
Componenta\Auth\Http\Strategy\MagicLink\Denied\TokenAlreadyUsed
Componenta\Auth\Http\Strategy\MagicLink\Denied\TokenExpired
```

Inject `TokenRequestQueueInterface` or `OtpRequestQueueInterface` directly. User lookup, challenge generation, persistence and sender I/O belong in `TokenRequestProcessor`/`OtpRequestProcessor`, outside the HTTP request thread.

Magic-link verification now collapses all negative token states to `InvalidToken` on the public path.

The generic magic-link request handler no longer accepts a user-controlled `redirect`. Redirect targets are an application routing/security decision and must be added only after an application-specific allowlist or route policy.

## JWT profile

`JwtConfig` requires an explicit non-empty issuer and audience:

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

Access-token validation checks the signature, exact issuer/audience/type, `iat`, optional `nbf`, `exp`, clock skew and maximum configured access lifetime. Signers emit `typ` and reject custom claims that replace registered claims.

HMAC secrets must meet the digest-size minimum for the selected algorithm. `RefreshTokenGenerator` accepts 32–64 bytes only.

## Built-in refresh store

`RefreshTokenStoreInterface` has a secure default binding: `DatabaseRefreshTokenStore`.

The store owns these atomic transitions:

- `storeInitial()` creates the first token and family state;
- `rotateAtomically()` serializes validation, presented-token consumption, replay compromise and successor insertion;
- `revoke()` serializes with concurrent family transitions;
- `revokeAllForSubject()` performs ordinary family revocation without falsely marking replay compromise.

Only SHA-256 representations of bearer token IDs are persisted. A separate family row is mutated on every family transition and acts as the serialization point. If successor insertion fails, the database transaction rolls the presented-token claim back.

Actual reuse marks the family compromised and revokes active descendants. Ordinary revoke-all sets family revocation state instead; a later presentation is invalid, not reported as replay.

Minimum schema contract:

```text
refresh_token_families
  family_id       PRIMARY KEY or UNIQUE
  user_id         NOT NULL, indexed
  revoked_at      nullable
  compromised_at  nullable
  lock_nonce      NOT NULL

refresh_tokens
  token_hash      PRIMARY KEY or UNIQUE
  family_id       NOT NULL, indexed/FK to family_id
  user_id         NOT NULL, indexed
  expires_at      NOT NULL
  consumed_at     nullable
  revoked_at      nullable
```

`token_hash` must hold a 64-character SHA-256 hex value. Do not persist the bearer token itself.

Consumed members of a still-relevant refresh family are security history used for replay detection. Do not delete them merely to reduce row count. Cleanup of terminal/expired families must preserve the application's replay-detection requirements.

Custom refresh stores must provide equivalent atomic rotation, rollback, family serialization, replay compromise, ordinary revocation and primary-read guarantees. Rebuilding the former `find -> revoke -> store` sequence reintroduces the race.

## OTP profile and built-in store

`OtpConfig` is now a real DI/config service. The built-in OOB profile accepts:

```php
'auth' => [
    'otp' => [
        'length' => 6,       // 6..18 decimal digits
        'ttl' => 300,        // 1..600 seconds
        'maxAttempts' => 5,
        'hmacKey' => $_ENV['AUTH_OTP_HMAC_KEY'],
        'store' => [
            'table' => 'otp_codes',
        ],
    ],
],
```

`length < 6` and `ttl > 600` are rejected. `maxAttempts` limits a single challenge; applications must also apply an account/destination-level rate limiter that survives challenge replacement/reissue.

`CodeStoreInterface` defaults to `DatabaseCodeStore`. It persists a keyed verifier rather than the low-entropy numeric OTP:

```text
HMAC-SHA-256(destination || NUL || code, auth.otp.hmacKey)
```

Use a dedicated secret of at least 32 bytes. The default empty key is intentionally unusable and the SQL store factory fails fast until it is configured.

Minimum schema contract:

```text
otp_codes
  destination   PRIMARY KEY or UNIQUE
  user_id       NOT NULL
  challenge_id  NOT NULL
  verifier      NOT NULL
  expires_at    NOT NULL
  attempts      NOT NULL
```

`challenge_id` changes on replacement and is the optimistic version used by attempt updates and consume/expiry deletes. A verifier that started against an older challenge cannot mutate its replacement. Correct verification is single-winner because successful consumption conditionally deletes exactly that challenge version.

## Primary/write reads for credential state

Cycle Database may be configured with separate READ and WRITE drivers. Authentication state cannot safely depend on replica lag.

Built-in authoritative reads are pinned to `DatabaseInterface::WRITE` for:

- sessions;
- remember-me consumption;
- one-time token lookup/consumption;
- refresh token/family transitions;
- OTP verification state.

Deploy readers and corresponding credential writers together. Housekeeping may use a non-authoritative candidate read only when the final write rechecks the security predicate on the primary.

## Database timestamps

Built-in DATETIME credential stores use the sortable format `Y-m-d H:i:s` and serialize/parse timestamps in UTC. Supplying another `dateFormat` fails fast. Do not store local/DST-dependent credential expiry strings.

## Password reset

Register `PasswordResetServiceInterface`. The service, not the HTTP handler, owns password policy and the complete recovery transition.

`PasswordResetResult` includes a distinct `PasswordRejected` outcome. `Success` means the reset token was consumed, the password was changed, and pre-reset session, remember-me and refresh credentials were durably or logically invalidated.

The package cannot create one physical transaction around an application-owned password repository and every external credential store. When those resources differ, use credential versioning plus a transactional outbox/idempotent retry. Never return `Success` after a partial transition.

`PasswordUpdaterInterface` is removed.

## Session regeneration and transport lifecycle

Session rotation is now single-winner.

Once the old row is successfully claimed for regeneration, the presented old session ID becomes invalid immediately. `find($oldId)` does **not** resolve or disclose the successor ID. A concurrent request that loses regeneration is denied and must authenticate again.

`regenerationGracePeriod` is not an authentication grace period. It only permits operational retention of the replaced row/tombstone; it never makes the old bearer credential valid again.

Additional lifecycle changes:

- nested authentication layers share one request-scoped `CredentialTransportState`;
- only the owner of that state applies the final response mutation;
- `clear()` is terminal and wins over queued credential stores;
- `LogoutHandler` does not remove the same cookie twice when terminal middleware owns transport commit;
- touch rechecks active-session predicates and uses a conditional update;
- cleanup is bounded and rechecks expiry before delete;
- `SessionCollection::pluck()` rejects unknown keys;
- `SessionManagerInterface::exists()` means the presented session credential is currently active, not merely that a historical row exists.

Because a successfully rotated old ID is intentionally invalid immediately, applications should place an exception-to-response middleware outside the auth pipeline so an unrelated downstream exception does not leave the client retrying an already-rotated cookie. Do not restore old-ID-to-successor bridging as an error-recovery mechanism.

## Event semantics

Security-critical session lifecycle participants are synchronous and fail fast inside the owning database transition where applicable. Best-effort lifecycle observers run only after commit.

Generic `AuthenticationAttempted`, `AuthenticationSucceeded`, `AuthenticationDenied` and `LoggedOut` notifications are observers. Their failures are isolated and logged; an observer must not retroactively fail an already committed credential transition.

Credential-bearing DTOs and audit containers use redacted debug/JSON representations. `DeniedReasonInterface::$attributes` remains trusted audit context and is never part of the built-in HTTP denial payload.

## Malformed payload mapping

Strict extractors throw `InvalidPayloadException` for malformed client input. Built-in handlers should run behind `InvalidPayloadMiddleware` or an equivalent application exception mapper that turns it into a stable HTTP 400 response.

## One-time token storage

`TokenManagerInterface::replaceForSubject()` replaces a subject challenge atomically. The built-in SQL manager uses UPSERT, so the persistence schema must enforce a `UNIQUE` constraint on the canonical subject UUID column. Do not emulate replacement as independent `DELETE` and `INSERT` operations.

## Remember-me feature flag

Remember-me is disabled by default. Set `auth.rememberMe.enabled=true` only when intended. Enabling it activates the built-in termination and regeneration listeners required to keep remember-me credentials synchronized with session lifecycle.

## Bounded housekeeping

These public cleanup methods are bounded and return affected rows:

```php
SessionManagerInterface::cleanup(int $limit = 1000): int;
RememberMeTokenManagerInterface::cleanup(int $limit = 1000): int;
TokenManagerInterface::cleanup(int $limit = 1000): int;
```

Run them from a worker, cron task or scheduler instead of unbounded request-path cleanup.

## Removed dead API

Removed in v2:

```text
AuthSubjectInterface
AuthSubject
SessionAwareInterface
PublicDeniedReasonInterface
RememberMeAwareInterface
PasswordUpdaterInterface
TokenRequester
OtpRequester
ConfigKey::COOKIE
ConfigKey::MAGIC_LINK
ConfigKey::PASSWORD_RESET
```

## Composer and runtime verification

The package declares its direct PSR-17 and PSR-15 handler dependencies (`psr/http-factory`, `psr/http-server-handler`) and requires PHP 8.4+.

The repository release gate runs the supported PHP/DI matrix:

```text
PHP 8.4 / DI 2.x
PHP 8.4 / DI 3.x
PHP 8.5 / DI 2.x
PHP 8.5 / DI 3.x
```

Each job runs syntax checks, PHPUnit, PHPStan max, dependency audit and whitespace checks. The database test suite exercises fast SQLite invariants and also runs the built-in UPSERT/CAS/refresh replay paths against a real MySQL 8.4 InnoDB service.

## Secure rollout order

1. Migrate every credential owner to canonical `IdentityInterface::$uuid` / `UuidInterface` contracts.
2. Remove `SessionAwareInterface`/`currentSessionId` from identity entities and use request/session-manager state explicitly.
3. Create or alter session, one-time, OTP and refresh tables with the documented constraints.
4. Configure explicit ordered strategies, the JWT profile, OTP profile/HMAC key and remember-me feature flag.
5. Deploy credential writers and primary-pinned readers together.
6. Register delivery queues/processors and `PasswordResetServiceInterface`.
7. Put strict handlers behind malformed-input mapping and endpoint-specific rate limits/CSRF protection as applicable.
8. Run the same DB/concurrency tests, PHPUnit, PHPStan and dependency audit before production rollout.
