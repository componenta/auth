# Quality and security gates

A v2 release is accepted only for the exact branch HEAD that passes every supported runtime and credential-lifecycle invariant.

## CI matrix

Every push/PR runs:

```text
PHP 8.4 / Componenta DI 2.x
PHP 8.4 / Componenta DI 3.x
PHP 8.5 / Componenta DI 2.x
PHP 8.5 / Componenta DI 3.x
```

Each job starts MySQL 8.4/InnoDB and enables SQLite, MySQL and `pcntl` for the CI-only concurrency harness.

The normal gate performs:

```text
composer validate --strict
composer check-platform-reqs
syntax lint: src + tests
PHPUnit
PHPStan level max: src + tests
composer audit
git diff --check
```

`tools/verify.sh` also prevents the return of removed identity/session capability APIs, event marker interfaces, `PublicDeniedReasonInterface`, `RememberMeToken`, delete-on-consume remember rotation and hidden clocks in event DTOs.

## Release-blocking invariants

The suite must prove:

1. logout clear is terminal and cannot be overwritten by queued session/remember mutations;
2. nested authentication layers retain the storage associated with each credential mutation;
3. a denial can never carry a session or response credential;
4. strategy denial is terminal unless the strategy explicitly marks a soft failure;
5. missing credential storage fails before downstream business code executes;
6. request-local session state never lives on a reusable identity;
7. a replaced session ID becomes invalid immediately and never resolves to its successor;
8. session critical listeners are fail-fast inside the owning transition while observers run after commit;
9. remember-me is disabled by default and enabling it activates the critical lifecycle listeners;
10. remember bearer rotation is single-winner and concurrent logout/revocation leaves no descendant grant;
11. remember grants always bind to a session and revocation can match current or previous session lineage;
12. refresh rotation/replay is one family-serialized transition and actual replay leaves zero active descendants;
13. ordinary refresh revocation is distinct from replay compromise and failed successor persistence rolls back the presented-token claim;
14. OTP verification/attempt accounting/consume is single-winner over one challenge version;
15. public OTP failures do not reveal whether a challenge existed;
16. OTP input matches the configured code length before attempt accounting;
17. one-time tokens are domain-separated by purpose;
18. built-in delivery queue messages cannot look up one identity and deliver the credential to a different arbitrary destination;
19. password reset success represents the complete recovery transition and password-policy rejection is explicit;
20. denial attributes and bearer credentials are absent from public/debug serialization;
21. token-bearing responses are non-cacheable;
22. malformed inputs are rejected before provider/hash/storage work;
23. credential-state reads use the primary/write connection;
24. UUID providers cannot substitute a different identity;
25. credential DATETIME values are UTC with fixed internal representation;
26. cleanup operations are bounded and recheck security predicates before destructive writes;
27. event DTO timestamps come from owning clock services, not hidden global time.

## Real MySQL concurrency gate

`tools/verify-mysql-concurrency.php` uses `pcntl_fork`, a barrier and independent MySQL connections. It is deliberately separate from ordinary unit tests so races are not simulated as sequential calls.

It asserts:

### Refresh

Two workers rotate the same presented token concurrently with different successors. Exactly one transition initially rotates; the replay path compromises the family. After both complete, `revoked_at IS NULL` count for that family is zero.

### OTP

Two workers verify the same valid OTP concurrently. Exactly one returns `verified`; the other returns `invalid`, and the challenge row is gone.

### Remember-me versus logout

One worker rotates the remember bearer while another revokes the originating session. Regardless of ordering, no remember grant remains after both operations complete.

## Database-store conformance

SQLite provides deterministic rollback and edge-case coverage. MySQL 8.4 independently exercises dialect-sensitive UPSERT, CAS, FK and transaction behavior.

Security-state reads for session, remember-me, one-time, refresh and OTP stores are also tested with separate WRITE and intentionally stale/empty READ drivers. Moving an authoritative read to a replica therefore fails the suite.

`DatabaseRefreshTokenHousekeeper` is tested separately from rotation. Cleanup may remove only families whose complete token history is expired; active/replay-relevant history is retained.

## Application-owned obligations

The package does not own the application's password repository, message broker, scheduler, CSRF policy or endpoint rate limiter. Therefore the application must separately verify:

- its concrete `PasswordResetServiceInterface` completes password change plus old-credential invalidation before reporting success;
- queue adapters are durable/non-inline where uniform timing depends on asynchronous work;
- OTP/account rate limits survive challenge reissue;
- cookie-authenticated state-changing routes have the appropriate CSRF policy;
- custom credential stores pass equivalent concurrency and primary-read tests.

## Release decision

Green PHPUnit alone is insufficient. The **exact final HEAD** must have all four matrix jobs successful, including MySQL 8.4 integration, PHPStan max, Composer audit and the real concurrency gate.
