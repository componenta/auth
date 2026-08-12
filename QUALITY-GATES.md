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

`tools/verify.sh` also prevents the return of removed identity/session capability APIs, event marker interfaces, `PublicDeniedReasonInterface`, `RememberMeToken`, delete-on-consume remember rotation, hidden clocks in event DTOs, raw queued credential exposure, missing credential-response cache hardening, missing magic-link referrer hardening and floating GitHub Action refs.

## Release-blocking invariants

The suite must prove:

1. logout clear is terminal and cannot be overwritten by queued session/remember mutations;
2. nested authentication layers retain the storage associated with each credential mutation and preserve an existing session when a later successful layer authenticates the same UUID without returning a session;
3. a terminal denial produced by one `AuthenticationMiddleware` cannot be overwritten by a later authentication layer;
4. two independently successful credentials for different UUIDs in one nested authentication flow fail closed;
5. a later terminal nested denial cancels credential writes queued by an earlier successful layer;
6. a denial can never carry a session or response credential;
7. strategy denial is terminal unless the strategy explicitly marks a soft failure inside `Authenticator`;
8. missing credential storage fails before downstream business code executes;
9. request-local session state never lives on a reusable identity;
10. a replaced session ID becomes invalid immediately and never resolves to its successor;
11. terminating a presented session serializes with regeneration and cannot leave an already-created replacement descendant;
12. cleanup retains replaced-session lineage tombstones until absolute expiry, so a logout holding an older authenticated ID can still terminate its active successor after regeneration grace has elapsed;
13. session critical listeners are fail-fast inside the owning transition while observers run after commit;
14. remember-me is disabled by default and enabling it activates the critical lifecycle listeners;
15. remember bearer rotation is single-winner and concurrent logout/revocation leaves no descendant grant;
16. remember grants always bind to a session and revocation can match current or previous session lineage;
17. refresh rotation/replay is one family-serialized transition and actual replay leaves zero active descendants;
18. ordinary refresh revocation is distinct from replay compromise, revokes the complete family, serializes with rotation and cannot leave an active successor;
19. failed refresh-successor persistence rolls back the presented-token claim;
20. OTP verification/attempt accounting/consume is single-winner over one challenge version;
21. public OTP response code/body do not expose whether a challenge existed; this is not a claim of constant SQL latency;
22. OTP input matches the configured code length before attempt accounting;
23. one-time tokens are domain-separated by purpose;
24. built-in delivery queue messages cannot look up one identity and deliver the credential to a different arbitrary destination;
25. password reset success represents the complete recovery transition and password-policy rejection is explicit;
26. denial attributes and bearer credentials are absent from public/debug serialization, and `CredentialTransportState` does not expose queued bearer payloads;
27. every response-side credential store/remove mutation is non-cacheable, token-bearing responses are non-cacheable, and magic-link verification responses use `Referrer-Policy: no-referrer`;
28. malformed inputs are rejected before provider/hash/storage work;
29. credential-state reads use the primary/write connection;
30. UUID providers cannot substitute a different identity;
31. credential DATETIME values are UTC with fixed internal representation;
32. cleanup operations are bounded and recheck security predicates before destructive writes;
33. event DTO timestamps come from owning clock services, not hidden global time;
34. Componenta factory wiring honors the shared PSR-20 clock when the container provides it;
35. third-party GitHub Actions use immutable 40-character commit SHAs.
36. built-in `RateLimited` denials validate non-negative retry delay and publish it only as the standard `Retry-After` header, not in the JSON body.

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

Session cleanup is tested on both SQLite and MySQL. A replaced row is a lineage tombstone: after its short regeneration grace expires it is no longer an authenticatable credential, but cleanup retains it until absolute expiry so termination by the old presented ID can still traverse `replaced_by` to an active successor.

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
