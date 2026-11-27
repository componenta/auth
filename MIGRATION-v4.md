# Migrating from Auth 3 to Auth 4

Auth 4 keeps authentication mechanisms, transport and persistence in separate
packages. Upgrade the capabilities used by the application together so their
Composer constraints and credential-publication contracts agree.

## Coordinated package versions

| Package | Constraint |
| --- | --- |
| `componenta/auth` | `^4.0.0` |
| `componenta/auth-http` | `^2.0.0` |
| `componenta/auth-session` | `^2.0.0` |
| `componenta/auth-session-database` | `^2.0.0` |
| `componenta/auth-session-http` | `^3.0.0` |
| `componenta/auth-token` | `^1.0.1` |
| `componenta/auth-jwt` | `^2.0.0` |
| `componenta/auth-remember-me` | `^3.0.0` |
| `componenta/auth-password` | `^3.0.0` |
| `componenta/auth-magic-link` | `^3.0.0` |
| `componenta/auth-otp` | `^3.0.0` |
| `componenta/auth-recovery-code` | `^3.0.0` |
| `componenta/auth-totp` | `^3.0.0` |
| `componenta/auth-webauthn` | `^3.0.0` |
| `componenta/auth-app` | `^3.0.0` |
| `componenta/auth-session-app` | `^2.0.0` |

The browser stack uses `componenta/http-csrf-middleware ^4.0.0`. The packages use
`componenta/identity ^1.1.1`; components that depend on Componenta Clock use
`componenta/clock ^1.2.0`. These versions support the Config 4 dependency graph.
Core Auth has no direct Config or DI dependency. The two application adapters
require Config 4, DI 6 and PHP 8.5.13+. Other Auth packages retain PHP 8.4 support.
Password authentication requires `componenta/password ^2.0.0`: bcrypt passwords
longer than 72 bytes and passwords containing NUL are rejected. Existing accounts
that used a longer bcrypt password need a trusted password-reset flow; do not
truncate submitted passwords. Argon2 verification is not subject to that limit.

WebAuthn 3 requires the credential revision migration before deployment; see
[its schema upgrade instructions](https://github.com/componenta/auth-webauthn/blob/fix/auth-dependency-audit-2026-11-27/README.md#database-schema-upgrade).

## Denial results

Built-in denial reasons expose only their code through JSON serialization and
debug output. Read `$denial->attributes` explicitly for trusted audit processing;
do not rely on generic JSON serialization to publish those attributes to clients.
Keep response fields under the application's explicit control.

`RateLimited::$retryAfter` validates every assignment and rejects negative values.
It is now a hooked property, so taking a mutable reference to it is unsupported.
Read and assign the value directly:

```php
$denial = new RateLimited(30);
$denial->retryAfter = 60;
```

An `AuthenticationResult` subject must implement either `IdentityInterface` or
`DeniedReasonInterface`. Objects implementing both are rejected. Successful
results still require explicit `AuthenticationEvidence`.

## Context and event handling

`Context` owns its top-level attribute map. References in the input array cannot
replace stored values after construction. Numeric keys retain their PHP array-key
identity when attributes are merged. Nested values remain borrowed; objects used
as request-local transport state can still intentionally be mutable.

Use `AuthenticationGuardInterface` and credential-issuance admission for access
checks. Lifecycle observers do not enforce policy: listener, provider and lazy
iterator failures are isolated from the authentication outcome. Explicit
critical dispatch stops at the first failing critical listener before running
best-effort observers. Listener subscriptions name concrete event classes;
interface and abstract-class subscriptions are rejected at registration.

## Credential publication

Session HTTP 3 and Remember Me 3 defer grant publication when the request already
contains a `CredentialTransportState`. Their publishers return the unchanged
response after queueing the grant and its failure compensation. The owning
authentication middleware applies the final queue after downstream handling.

Code that inspected `Set-Cookie` immediately after calling a publisher must
instead inspect the completed outer response. Without an existing transport
state, publication remains immediate. Keep transport state local to one request;
the owning middleware must complete publication or discard pending work.

## Session persistence

Session Database 2 retains the schema published with version 1. No schema change
is required for that upgrade. Pre-1.0 development snapshots with an extra
`auth_sessions.created_at` column or constructor argument need the migration
described in the session package README; preserve `authenticated_at` and session
data. Capability packages can have separate migration requirements, including
the WebAuthn credential revision schema.

Initial authentication time stays unchanged during rotation. Fresh
reauthentication evidence is stored separately from cumulative evidence;
application policies must not treat a previously established stronger factor as
a newly performed proof.
