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

Third-party GitHub Actions are pinned to immutable full commit SHAs. `tools/verify.sh` rejects floating external action refs so upstream tag movement cannot silently alter the release gate.

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

`tools/verify.sh` also prevents the return of removed identity/session capability APIs, event marker interfaces, `PublicDeniedReasonInterface`, `RememberMeToken`, delete-on-consume remember rotation, hidden clocks in event DTOs, missing magic-link referrer hardening and floating GitHub Action refs.

## Release-blocking invariants

The suite must prove:

1. logout clear is terminal and cannot be overwritten by queued session/remember mutations;
2. nested authentication layers retain the storage associated with each credential mutation;
3. a denial can never carry a session or response credential;
4. strategy denial is terminal unless the strategy explicitly marks a soft failure;
5. missing credential storage fails before downstream business code executes;
6. request-local session state never lives on a reusable identity;
7. a replaced session ID becomes invalid immediately and never resolves to its successor;
8. terminating a presented session serializes with regeneration and cannot leave an already-created replacement descendant;
9. session critical listeners are fail-fast inside the owning transition while observers run after commit;
10. remember-me is disabled by default and enabling it activates the critical lifecycle listeners;
11. remember bearer rotation is single-winner and concurrent logout/revocation leaves no descendant grant;
12. remember grants always bind to a session and revocation can match current or previous session lineage;
13. refresh rotation/replay is one family-serialized transition and actual replay leaves zero active descendants;
14. ordinary refresh revocation is distinct from replay compromise, revokes the complete family, serializes with rotation and cannot leave an active successor;
15. failed refresh-successor persistence rolls back the presented-token claim;
16. OTP verification/attempt accounting/consume is single-winner over one challenge version;
17. public OTP response code/body do not expose whether a challenge existed; this is not a claim of constant SQL latency;
18. OTP input matches the configured code length before attempt accounting;
19. one-time tokens are domain-separated by purpose;
20. built-in delivery queue messages cannot look up one identity and deliver the credential to a different arbitrary destination;
21. password reset success represents the complete recovery transition and password-policy rejection is explicit;
22. denial attributes and bearer credentials are absent from public/debug serialization;
23. token-bearing responses are non-cacheable and magic-link verification responses use `Referrer-Policy: no-referrer`;
24. malformed inputs are rejected before provider/hash/storage work;
25. credential-state reads use the primary/write connection;
26. UUID providers cannot substitute a different identity;
27. credential DATETIME values are UTC with fixed internal representation;
28. cleanup operations are bounded and recheck security predicates before destructive writes;
29. event DTO timestamps come from owning clock services, not hidden global time;
30. Componenta factory wiring honors the shared PSR-20 clock when the container provides it;
31. third-party GitHub Actions use immutable 40-character commit SHAs.

## Real MySQL concurrency gate

`tools/verify-mysql-concurrency.php` uses `pcntl_fork`, a barrier and independent MySQL connections. It is deliberately separate from ordinary unit tests so races are not simulated as sequential calls.

It asserts:

### Refresh rotation versus replay

Two workers rotate the same presented token concurrently with different successors. Exactly one transition initially rotates; the replay path compromises the family. After both complete, `revoked_at IS NULL` count for that family is zero.

### Refresh rotation versus ordinary revocation

One worker rotates a presented refresh bearer while another ordinarily revokes that bearer. If revocation wins first, rotation is invalid. If rotation commits first, revocation waits for family serialization and revokes the successor. In both orderings the family is ordinarily revoked, `compromised_at` remains `NULL`, and no active token remains.

### OTP

Two workers verify the same valid OTP concurrently. Exactly one returns `verified`; the other returns `invalid`, and the challenge row is gone.

### Remember-me versus logout

One worker rotates the remember bearer while another revokes the originating session. Regardless of ordering, no remember grant remains after both operations complete.

### Session regeneration versus logout

One worker regenerates the authenticated session while another logout path terminates the presented old session. Regardless of ordering, termination cannot leave an active replacement session.

## Database-store conformance

SQLite provides deterministic rollback and edge-case coverage. MySQL 8.4 independently exercises dialect-sensitive UPSERT, CAS, FK and transaction behavior.

Security-state reads for session, remember-me, one-time, refresh and OTP stores are also tested with separate WRITE and intentionally stale/empty READ drivers. Moving an authoritative read to a replica therefore fails the suite.

`DatabaseRefreshTokenHousekeeper` is tested separately from rotation. Cleanup may remove only families whose complete token history is expired; active/replay-relevant history is retained.

The built-in session table contains live session identifiers because enumeration and replacement-lineage management require recoverable IDs. The database is therefore part of the credential trust boundary even though session DTO debug/JSON output redacts IDs.

## Application-owned obligations

The package does not own the application's password repository, message broker, scheduler, reverse proxy, browser history, CSRF policy or endpoint rate limiter. Therefore the application must separately verify:

- its concrete `PasswordResetServiceInterface` completes password change plus old-credential invalidation before reporting success;
- OTP and one-time-token queue adapters are durable/non-inline where uniform account-existence request timing matters;
- OTP/account rate limits survive challenge reissue and protect verification as well as request endpoints;
- OTP public response semantics are uniform, but deployment must not assume constant latency across missing/existing SQL challenge states;
- cookie-authenticated state-changing routes have the appropriate CSRF policy;
- `LogoutHandler` is placed after authentication when server-side session termination is expected;
- magic-link query credentials are redacted from reverse-proxy/access logs and verification pages do not load untrusted third-party resources;
- access to credential-bearing session persistence and database logs is restricted;
- custom credential stores pass equivalent concurrency and primary-read tests and honor the strengthened family/session-lineage contracts.

## Release decision

Green PHPUnit alone is insufficient. The **exact final HEAD** must have all four matrix jobs successful, including MySQL 8.4 integration, PHPStan max, Composer audit and the real concurrency gate.
