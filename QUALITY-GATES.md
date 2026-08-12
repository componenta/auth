# Quality and security gates

Version 2 is released only after the repository checks the same credential-lifecycle invariants on every supported runtime combination.

## CI matrix

GitHub Actions runs `tools/verify.sh` on:

- PHP 8.4 with Componenta DI 2.x;
- PHP 8.4 with Componenta DI 3.x;
- PHP 8.5 with Componenta DI 2.x;
- PHP 8.5 with Componenta DI 3.x.

Every matrix job starts a real MySQL 8.4 service in addition to the fast SQLite fixtures. `pdo_sqlite` and `pdo_mysql` are enabled so database-specific UPSERT, CAS and transaction behavior is exercised rather than inferred from SQLite compatibility.

The verification script performs:

```text
composer validate --strict
composer check-platform-reqs
PHP syntax lint for src and tests
PHPUnit (SQLite + MySQL 8.4 integration when CI env is present)
PHPStan level max
composer audit
git diff --check
```

It also rejects removed compatibility symbols, mutable request-local identity state, non-canonical owner-ID contracts and temporary remediation artifacts.

## Release-blocking invariants

The package test suite must prove that:

1. logout clear is terminal and cannot be overwritten by session or remember-me rotation;
2. current session state is request-scoped and never stored on a reusable identity;
3. a replaced session ID is invalid immediately, cannot resolve to its successor, and concurrent regeneration has one winner;
4. session lifecycle critical participants fail fast inside the owning transition while already-committed generic auth/logout observers are best-effort;
5. refresh rotation is one storage-level atomic transition and actual replay compromises the whole family;
6. ordinary refresh-family revocation remains distinct from replay compromise, and failed successor insertion rolls the presented-token claim back;
7. OTP verification, attempt accounting and consumption use one versioned challenge and a stale verifier cannot mutate its replacement;
8. OTP configuration cannot weaken the built-in OOB profile below six decimal digits or extend a challenge beyond ten minutes;
9. successful password reset represents password change plus invalidation of prior long-lived credentials, while password-policy rejection is explicit;
10. public denial responses and direct debug/JSON serialization do not expose trusted audit context or bearer credentials;
11. credential-bearing responses are non-cacheable;
12. malformed credentials are rejected before provider, hashing or storage work;
13. enabled remember-me issuance includes its critical termination and regeneration listeners;
14. authentication-state reads use the primary/write database connection rather than a potentially lagging read replica;
15. UUID-based providers cannot substitute a different identity for the UUID requested by a credential;
16. built-in DATETIME credential stores normalize timestamps to UTC and reject unsafe date formats.

## Built-in database-store conformance

The default Cycle DB adapters are exercised by integration tests.

SQLite tests provide fast failure-injection and deterministic coverage. MySQL 8.4/InnoDB integration tests independently exercise the dialect-sensitive paths:

- one-time-token replacement through the built-in UPSERT;
- OTP replacement plus versioned verify/consume CAS;
- refresh-token rotation followed by replay-family compromise.

The broader store suite verifies that:

- `DatabaseRefreshTokenStore` stores only SHA-256 token representations, serializes a token family through its family row, keeps ordinary `revoked_at` separate from replay `compromised_at`, revokes active descendants after actual replay and keeps rotation transactional;
- `DatabaseCodeStore` stores an HMAC-SHA-256 verifier, uses a changing `challenge_id` as the optimistic version and makes successful verification single-winner;
- session regeneration cannot bridge a presented old ID to a successor and rollback/failure paths do not disclose the successor;
- session cleanup rechecks expiry at delete time;
- session, remember-me, one-time, refresh and OTP credential reads are tested with separate WRITE and intentionally stale/empty READ drivers, so moving security-state reads to a replica fails the test.

The built-in stores require the documented schema constraints. Refresh token hashes and family IDs must be unique, refresh families must persist distinct revocation/compromise state, OTP destination must identify one current challenge, one-time-token replacement requires canonical-subject uniqueness, and ownership columns store the canonical identity UUID.

## Secret-handling gate

Reusable credentials and trusted audit metadata are not public serialization formats. Regression tests cover redaction for credential payloads, refresh tokens, OTP storage DTOs, sessions, remember-me records, session collections, lifecycle/audit events, authentication results, contexts and denial reasons.

Redaction does not remove programmatic access required by a strategy/store/listener. It only prevents an accidental `json_encode()`, debug dump or generic event serialization from becoming a credential-disclosure path.

## Application-adapter conformance

Applications may replace built-in stores. A custom `RefreshTokenStoreInterface` or `CodeStoreInterface` must pass equivalent concurrency, replay, ordinary-revocation, rollback, primary-read and failure-injection tests; implementing the PHP interface alone is not proof of the security contract.

`PasswordResetServiceInterface`, delivery queues and cleanup schedulers remain application-owned because the package does not own the application's password/account transaction, queue technology or scheduler. Applications must verify those adapters separately and must enforce route-level CSRF protection and endpoint/account-specific rate limits where applicable.

In particular, `OtpConfig::$maxAttempts` limits one challenge only. An application-level account/destination limiter must survive challenge replacement so requesting a new code cannot reset brute-force protection.

## Release decision

A release candidate is not considered fixed or releasable merely because PHPUnit passes. The exact final branch HEAD must have all four matrix jobs successful, including MySQL 8.4 integration, PHPStan max, Composer audit and `git diff --check`.
