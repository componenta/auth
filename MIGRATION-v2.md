# Migrating to componenta/auth v2

Version 2 intentionally changes several storage and composition contracts. The old APIs could not enforce the credential-lifecycle invariants required for concurrent and partially failing authentication flows.

## Required application changes

### Ordered authenticator composition

Define every active strategy explicitly and in security-sensitive order:

```php
'auth' => [
    'strategies' => [
        SessionStrategy::class,
        RememberMeStrategy::class,
        JwtStrategy::class,
    ],
    'events' => true,
],
```

`AuthenticatorInterface` is now built by `AuthenticatorFactory`. Empty, duplicate, missing and non-strategy services fail fast.

### Refresh token store

Implement the new `RefreshTokenStoreInterface`:

- `storeInitial()` persists the first member of a family;
- `rotateAtomically()` serializes lookup, expiry validation, revocation, successor creation and replay compromise;
- `revokeAllForUser()` is required for account recovery.

A compliant store needs durable family/grant state. After `Reused`, no active token may remain in that family and no concurrent transaction may insert a new active descendant.

### OTP store

Replace `find()/incrementAttempts()/consume()` with `verifyAndConsume()`. Attempt accounting, expiry, constant-time comparison and consume must operate on the same locked or versioned challenge record.

### Password reset

Register an application implementation of `PasswordResetServiceInterface`. `Success` means one completed security transition: reset token consumed, password changed, and all old session, remember-me and refresh credentials durably or logically invalidated. For multiple stores, use a credential version plus transactional outbox/idempotent retry.

### Uniform delivery queues

`TokenRequester` and `OtpRequester` enqueue opaque requests only. Register queue adapters and run `TokenRequestProcessor` / `OtpRequestProcessor` in a worker. Provider lookup and sender I/O no longer occur on the HTTP request path, preventing account-enumeration timing differences.

### Session lifecycle

- `TouchSessionMiddleware` now requires a `PayloadStorageInterface`.
- `AuthenticationResult::$attributes` carries the already verified `SessionInterface`.
- `SessionManagerInterface::touch()` accepts the resolved last-active timestamp and throttles writes via `auth.session.touchInterval` (60 seconds by default).
- `cleanup(int $limit)` is bounded and must be invoked by a scheduler/worker. HTTP middleware only schedules work through `SessionCleanupSchedulerInterface`.
- `RememberMeTokenManagerInterface::revokeForSessions()` replaces per-session deletion loops.

### Events and denial responses

Generic authentication events contain `payloadType`, never the raw password, OTP or bearer payload. `DeniedReasonInterface::$attributes` is audit context and is not public. Implement `PublicDeniedReasonInterface` only for explicitly allowlisted public fields.

### Input and platform requirements

`ext-mbstring` is required. Password and OTP extractors reject arrays, objects, oversized values and unknown boolean representations. Map `InvalidPayloadException` to HTTP 400 with `InvalidPayloadMiddleware` or equivalent application middleware.

## Secure rollout order

Update storage adapters before deploying handlers that call the new contracts. Refresh-store schema and code must ship atomically. Do not emulate `rotateAtomically()` by calling the former methods in sequence; that preserves the replay race this release removes.
