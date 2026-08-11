# Migrating to componenta/auth v2

Version 2 intentionally changes storage, identity, composition and property contracts. The former APIs could not enforce credential-lifecycle invariants under concurrency, partial failure, replica lag and long-running workers.

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

Magic-link verification collapses negative outcomes to `InvalidToken`; the removed denial classes had no execution path.

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
    'rememberMe' => [
        'enabled' => true,
    ],
],
```

Empty, duplicate, missing and non-strategy services fail fast. The built-in `RememberMeStrategy` also requires `auth.rememberMe.enabled=true`; this prevents enabling credential issuance/consumption without the critical termination and regeneration listeners required by the feature.

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

## Built-in refresh store

`RefreshTokenStoreInterface` now has a secure default binding: `DatabaseRefreshTokenStore`.

The store owns these atomic transitions:

- `storeInitial()` persists the first family member;
- `rotateAtomically()` serializes validation, presented-token consumption, replay compromise and successor creation;
- `revoke()` serializes with concurrent family transitions;
- `revokeAllForSubject()` marks existing subject families revoked and revokes their active tokens without falsely labelling them compromised.

The implementation persists only SHA-256 representations of bearer token IDs. A separate family row is mutated on every family transition and acts as the serialization point. If successor insertion fails, the database transaction rolls the presented-token claim back. Actual replay marks the family `compromised_at` and revokes active descendants before returning `Reused`; ordinary revoke-all marks `revoked_at`, so a later presentation is `Invalid`, not `TokenFamilyCompromised`.

Default configuration:

```php
'auth' => [
    'jwt' => [
        'refreshStore' => [
            'tokenTable' => 'refresh_tokens',
            'familyTable' => 'refresh_token_families',
            'columns' => [
                'tokenHash' => 'token_hash',
                'familyId' => 'family_id',
                'subjectId' => 'user_id',
                'expiresAt' => 'expires_at',
                'consumedAt' => 'consumed_at',
                'revokedAt' => 'revoked_at',
                'familyRevokedAt' => 'revoked_at',
                'compromisedAt' => 'compromised_at',
                'lockNonce' => 'lock_nonce',
            ],
        ],
    ],
],
```

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

`token_hash` must be able to hold a 64-character SHA-256 hex value. Do not persist the bearer token ID itself. The family `familyRevokedAt` and `compromisedAt` states are distinct even if token and family tables both use a column named `revoked_at` in their own tables.

If the application overrides `RefreshTokenStoreInterface`, the replacement must provide equivalent atomic rotation, rollback, family replay compromise, ordinary-revocation semantics and primary-read guarantees. Do not rebuild the old `find -> revoke -> store` sequence around the interface.

## Built-in OTP store

`CodeStoreInterface` now defaults to `DatabaseCodeStore`.

The store persists a keyed verifier rather than the low-entropy numeric OTP:

```text
HMAC-SHA-256(destination || NUL || code, auth.otp.hmacKey)
```

Configure a dedicated secret of at least 32 bytes:

```php
'auth' => [
    'otp' => [
        'hmacKey' => $_ENV['AUTH_OTP_HMAC_KEY'],
        'store' => [
            'table' => 'otp_codes',
        ],
    ],
],
```

The default key is empty intentionally. `DatabaseCodeStoreFactory` fails fast until a valid application secret is supplied. Do not reuse a JWT signing key.

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

`challenge_id` is regenerated on every replacement and is the optimistic version for attempt updates and consume/expiry deletes. A verification that started on an older challenge cannot consume or increment attempts on a replacement challenge. A correct code is single-winner because successful verification conditionally deletes exactly that challenge version.

Custom `CodeStoreInterface` implementations must preserve the same versioned challenge, single-winner, bounded-attempt and primary-read semantics.

## Primary/write reads for credential state

This is an important migration requirement when Cycle Database is configured with a separate READ driver.

Cycle `Database::select()` normally uses the READ driver, while credential mutation uses the WRITE driver. Reading authentication state from a lagging replica can resurrect a terminated session, observe an obsolete one-time challenge or make a security transition reason about stale rows.

V2 therefore pins authoritative credential-state reads to `DatabaseInterface::WRITE` in the built-in:

- `DatabaseSessionManager` (`exists`, `find`, regeneration source and active-session collection);
- `DatabaseRememberMeTokenManager::consume()`;
- `TokenManager::find()`;
- `DatabaseRefreshTokenStore`;
- `DatabaseCodeStore`.

Deploy these readers and the corresponding writers together. Do not route them through an eventually consistent replica. Bounded housekeeping may still select candidates on a read replica when the actual delete rechecks the expiry/used predicate on the primary.

## Password reset

Register `PasswordResetServiceInterface`. The service receives the plaintext reset token and new password, validates/locks the token before expensive hashing, and owns the complete security transition. `PasswordResetResult::Success` means: reset token consumed, password changed, and old session, remember-me and refresh credentials invalidated.

`PasswordUpdaterInterface` has been removed because the HTTP handler no longer orchestrates the security transition itself.

A generic library cannot create one physical transaction across an application-owned password repository and every credential store. If they are separate resources, use credential versioning plus a transactional outbox and idempotent retry; never return `Success` after a partial transition.

## Session and transport lifecycle

- Nested authentication/session middleware layers reuse one request-scoped `CredentialTransportState`; only its owner applies the final mutation.
- A new authentication result removes stale identity, denial and session request attributes before installing the current result.
- `LogoutHandler` no longer performs a duplicate cookie removal when `AuthenticationMiddleware` owns terminal transport commit.
- Custom authentication middleware must attach the verified `SessionInterface` if logout should terminate that server-side session.
- Session touch rechecks idle/absolute expiry.
- Session cleanup is bounded and rechecks expiry before delete.
- Session termination/regeneration executes critical lifecycle listeners inside the database transaction; best-effort observers run only after commit.
- `SessionCollection::pluck()` rejects unknown keys.

## Malformed payload mapping

Strict auth extractors throw `InvalidPayloadException` for malformed client input. Built-in handlers must run behind `InvalidPayloadMiddleware` or an equivalent application exception mapper that turns this exception into a stable HTTP 400 response.

Without that mapping malformed-input behavior is delegated to the application's global exception handler and is not a supported production composition.

## One-time token storage

`TokenManagerInterface::replaceForSubject()` replaces a subject challenge atomically. The built-in SQL manager uses an UPSERT, so the persistence schema must enforce a `UNIQUE` constraint on the canonical subject UUID column. Do not emulate replacement as independent `DELETE` and `INSERT` statements.

## Remember-me feature flag

Remember-me is disabled by default. Set `auth.rememberMe.enabled=true` only when the feature is intended to be active. Enabling it automatically adds the built-in termination and regeneration listeners; custom listener lists are deduplicated.

## Housekeeping signatures

The following methods are bounded and return affected rows:

```php
SessionManagerInterface::cleanup(int $limit = 1000): int;
RememberMeTokenManagerInterface::cleanup(int $limit = 1000): int;
TokenManagerInterface::cleanup(int $limit = 1000): int;
```

Invoke them from a worker, cron task or scheduler.

## Composer requirements

The package declares its direct PSR-17 and PSR-15 handler dependencies:

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

1. Update identity/provider contracts to canonical UUID ownership.
2. Create/alter refresh family/token and OTP challenge tables with the constraints above, including both family `revoked_at` and `compromised_at`.
3. Configure `auth.otp.hmacKey` and the explicit JWT profile.
4. Deploy credential writers and the primary-pinned credential readers together.
5. Register delivery queues/processors and the application `PasswordResetServiceInterface`.
6. Configure ordered authentication strategies and remember-me feature state.
7. Put strict auth handlers behind `InvalidPayloadMiddleware` or an equivalent 400 mapper.
8. Run DB integration/concurrency tests, PHPUnit, PHPStan and dependency audit before production rollout.
