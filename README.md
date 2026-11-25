# Componenta Auth 3

Transport-neutral authentication contracts and orchestration for Componenta applications on PHP 8.4+.

Auth 3 is intentionally a small core. Concrete login mechanisms, HTTP integration,
sessions and persistence live in separate packages.

## Core responsibilities

`componenta/auth` owns:

- `AuthenticatorInterface` / `Authenticator`;
- ordered `AuthenticationStrategyInterface` strategies;
- immutable `ContextInterface` request/attempt context;
- `AuthenticationResult`;
- `AuthenticationEvidence`;
- `AuthenticationGuardInterface`;
- `AuthenticationStateInterface`;
- canonical `IdentityProviderInterface`;
- generic denial types and authentication lifecycle events.

It does **not** depend on PSR HTTP, Componenta DI, Cycle Database, password
libraries, JWT libraries or provider SDKs.

## Package boundaries

Install only the capabilities your application uses:

- `componenta/auth-http` — PSR-7/15/17 transport, middleware and credential publication.
- `componenta/auth-app` — invocation-only `#[CurrentUser]`.
- `componenta/auth-session` — authentication-session contracts and lifecycle.
- `componenta/auth-session-database` — Cycle Database persistence.
- `componenta/auth-session-http` — secure browser session, pre-auth transport and session-bound CSRF.
- `componenta/auth-session-app` — invocation-only `#[CurrentSession]`.

Password, OTP, remember-me, magic-link, password-reset, JWT, WebAuthn, TOTP
and recovery-code support belong to their own capability packages.

`componenta/session` is unrelated to authentication sessions and is not a
dependency of this package family.

## Authentication result

A denial is terminal by default. A strategy can explicitly mark a denial as a
soft failure when a later strategy is allowed to continue.

Successful authentication must always provide explicit evidence:

```php
return new AuthenticationResult(
    subject: $identity,
    evidence: new AuthenticationEvidence(
        methods: ['webauthn'],
        capabilities: ['user_verified', 'phishing_resistant'],
    ),
);
```

A successful result without `AuthenticationEvidence` is rejected. Auth 3 does
not silently assign an assurance level from a role or method name.

A result may additionally carry:

- one opaque `transportPayload` for an outer transport package;
- one non-secret `AuthenticationStateInterface` object owned by a capability package.

There is no generic artifacts/result bag.

## Context

`Context` remains a small immutable request/attempt-scoped value carrier.
Transport layers may provide request-local values such as a PSR-7 request or
credential publication state.

The top-level attribute map is a snapshot: later writes to the input array or
its directly referenced entries do not replace stored values. String keys,
including numeric strings, keep their PHP array-key identity when attributes
are added or merged. Existing keys are replaced by `withAttributes()`.

Attribute values are borrowed. Objects and references nested inside array
values are not deep-cloned or frozen. Use immutable values for authentication
policy; request-local transport state may intentionally remain mutable.

Long-lived services, repositories and loggers remain constructor dependencies;
`Context` is not a service locator.

## Guards

Use `AuthenticationGuardInterface` for fail-closed subject checks that must
apply across every authentication mechanism, such as disabled/deleted account
state.

Guards are not authorization policies. Roles and permissions remain application
authorization concerns.

## Events and decorator order

Place lifecycle observation outside guard evaluation so the published outcome
includes the final subject checks:

```php
$authenticator = new EventingAuthenticator(
    new GuardedAuthenticator(new Authenticator(...$strategies), ...$guards),
    new EventDispatcher($listeners, $logger),
);
```

`EventingAuthenticator` publishes metadata through observational dispatch.
Listener failures, provider failures and lazy-iterator failures are isolated;
logging failures cannot replace the authentication result. Critical dispatch is
an explicit separate operation and still propagates errors. Do not use lifecycle
observers to enforce authentication policy or transaction integrity.

`PriorityListenerProvider` matches concrete event classes exactly. Interface
and abstract-class subscriptions are rejected when registered. Higher priorities
run first, and equal priorities keep registration order.

Handlers that create credentials must run admission checks before issuance.
Wrapping a side-effecting strategy in `GuardedAuthenticator` does not roll back
work that the strategy already committed.

Built-in denial reasons expose only their code through JSON and debug output.
Trusted code can still read audit attributes explicitly.

## Authentication sessions

`componenta/auth-session` separates:

- public `AuthSession::$uuid`;
- secret `SessionCredential`.

The secret credential contains 32 random bytes encoded as unpadded base64url and
is never a management identifier.

Initial browser login uses a separate short-lived pre-authentication transaction.
The pre-auth credential and request token are consumed exactly once and are never
promoted into the authenticated session.

## Security model

The package family is designed to support OWASP ASVS-oriented applications, but
installing the packages does not itself establish an ASVS or NIST assurance claim.
Applications still own authentication policy, factor combinations, recovery,
timeouts, deployment, logging and authorization.

See `MIGRATION-v3.md` for the Auth 2 -> Auth 3 package map.
