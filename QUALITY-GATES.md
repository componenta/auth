# Quality and security gates

Version 2 is released only after the repository checks the same credential-lifecycle invariants on every supported runtime combination.

## CI matrix

GitHub Actions runs `tools/verify.sh` on:

- PHP 8.4 with Componenta DI 2.x;
- PHP 8.4 with Componenta DI 3.x;
- PHP 8.5 with Componenta DI 2.x;
- PHP 8.5 with Componenta DI 3.x.

The verification script performs:

```text
composer validate --strict
composer check-platform-reqs
PHP syntax lint for src and tests
PHPUnit
PHPStan level max
composer audit
git diff --check
```

It also rejects removed compatibility symbols, a mutable `currentSessionId`, non-canonical owner-ID contracts and temporary remediation artifacts.

## Release-blocking invariants

The package test suite must prove that:

1. logout clear is terminal and cannot be overwritten by session or remember-me rotation;
2. the current session is request-scoped and never stored on a reusable identity;
3. session regeneration and critical revocation rollback on failure, while best-effort observers run only after commit;
4. refresh rotation is one storage-level atomic transition and actual replay compromises the whole family;
5. ordinary refresh-family revocation remains distinct from replay compromise, and a failed refresh-successor insert rolls the presented-token claim back;
6. OTP verification, attempt accounting and consumption use one versioned challenge and a stale verifier cannot mutate its replacement;
7. successful password reset represents password change plus invalidation of prior long-lived credentials;
8. public denial responses do not serialize trusted audit context;
9. credential-bearing responses are non-cacheable;
10. malformed credentials are rejected before provider, hashing or storage work;
11. enabled remember-me issuance includes its critical termination and regeneration listeners;
12. authentication-state reads use the primary/write database connection rather than a potentially lagging read replica.

## Built-in database-store conformance

The default Cycle DB adapters are exercised by integration tests:

- `DatabaseRefreshTokenStore` stores only SHA-256 token representations, serializes a token family through its family row, keeps ordinary `revoked_at` separate from replay `compromised_at`, revokes active descendants after actual replay and keeps rotation transactional;
- `DatabaseCodeStore` stores an HMAC-SHA-256 verifier, uses a changing `challenge_id` as the optimistic version and makes successful verification single-winner;
- session, remember-me, one-time, refresh and OTP credential reads are tested with separate WRITE and intentionally empty READ drivers. If a security-state read accidentally moves to the replica, the test fails instead of silently accepting replica lag.

The built-in stores require the documented schema constraints. In particular, refresh token hashes and family IDs must be unique, refresh families must persist distinct revocation and compromise state, OTP destination must identify one current challenge, and ownership columns must store the canonical identity UUID.

## Application-adapter conformance

Applications may replace any built-in store. A custom `RefreshTokenStoreInterface` or `CodeStoreInterface` must pass equivalent concurrency, replay, ordinary-revocation, rollback, primary-read and failure-injection tests; implementing the interface alone is not sufficient proof of the security contract.

`PasswordResetServiceInterface`, delivery queues and cleanup schedulers remain application-owned because the package does not own the application's password/account transaction, queue technology or scheduler. Applications must verify those adapters separately and must enforce route-level CSRF protection and endpoint-specific rate limits where applicable.
