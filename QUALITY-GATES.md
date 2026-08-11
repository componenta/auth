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
3. session regeneration and critical revocation rollback on failure;
4. refresh rotation is one storage-level atomic transition and replay compromises the whole family;
5. OTP verification, attempt accounting and consumption act on one locked or versioned challenge;
6. successful password reset represents password change plus invalidation of prior long-lived credentials;
7. public denial responses do not serialize trusted audit context;
8. credential-bearing responses are non-cacheable;
9. malformed credentials are rejected before provider, hashing or storage work;
10. enabled remember-me issuance includes its critical termination and regeneration listeners.

## Application-adapter conformance

The repository cannot prove the implementation of application-owned refresh, OTP, password-reset, queue or scheduler adapters. A consuming application must run equivalent concurrency, rollback and failure-injection tests against its concrete stores and must enforce the documented schema constraints, CSRF protection and endpoint-specific rate limits.
