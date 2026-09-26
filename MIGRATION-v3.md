# Migrating from componenta/auth 2.x to Auth 3

Auth 3 keeps the proven Authenticator/strategy/Context model, but changes package
boundaries and the authentication-session contract.

## Core

Kept in `componenta/auth`:

- `AuthenticatorInterface`;
- `Authenticator`;
- `AuthenticationStrategyInterface`;
- `ContextInterface` / `Context`;
- denial contracts;
- authentication lifecycle events.

New:

- `AuthenticationEvidence`;
- `AuthenticationGuardInterface`;
- `AuthenticationStateInterface`;
- `IdentityProviderInterface`.

Successful `AuthenticationResult` now requires explicit
`AuthenticationEvidence`.

## HTTP

Move imports from `Componenta\Auth\Http\...` to the
`componenta/auth-http` package. Namespace compatibility is intentionally kept
as `Componenta\Auth\Http\...` where practical.

`CredentialTransportState` remains the response-publication/rollback primitive.

## Sessions

Removed from Auth core:

```text
SessionInterface
SessionManagerInterface
SessionAwareInterface
DatabaseSessionManager
SessionCollection*
TouchSessionMiddleware
SessionGarbageCollectionMiddleware
```

Replace with:

```text
componenta/auth-session
componenta/auth-session-database
componenta/auth-session-http
componenta/auth-session-app
```

The public session management identifier is now:

```php
$session->uuid
```

The browser bearer is a separate secret:

```php
SessionCredential
```

Do not expose or persist the raw credential.

`IdentityInterface` no longer owns active sessions. Remove
`SessionAwareInterface` and request-local session collections from identity
objects.

Use `#[CurrentSession] AuthSession $session` when invocation code needs the
current authentication session. There is no `CurrentSessionId` or
`CurrentSessionReference`; read `$session->uuid`.

## Browser login

Do not promote guest/pre-login state to authenticated state.

Use the pre-authentication transaction from `componenta/auth-session` +
`auth-session-database` + `auth-session-http`:

1. create a short-lived pre-auth grant;
2. publish its HttpOnly `__Host-` credential cookie;
3. keep the separate request token in client memory and send it in the configured header;
4. consume both values atomically when completing login;
5. issue a fresh `AuthSession::$uuid` and fresh `SessionCredential`.

## CSRF

Session CSRF no longer needs a mutable secret field on the session record.
`componenta/auth-session-http` derives a synchronizer token from the public
session UUID + credential generation using a server key. Session credential
rotation invalidates the old CSRF token automatically.

## Concrete authentication methods

Concrete Auth 2 features no longer belong in `componenta/auth`.

Migration targets:

| Auth 2 capability | Auth 3 package family |
| --- | --- |
| sessions | auth-session* |
| remember-me | auth-remember-me* |
| password | auth-password* |
| one-time token | auth-token* |
| magic link | auth-magic-link* |
| password reset | auth-password (using auth-token purpose=password_reset) |
| JWT / refresh grants | auth-jwt* |
| OTP | auth-otp* |
| reauthentication | auth-session + concrete factor package (auth-otp/auth-webauthn/auth-totp/auth-recovery-code) |
| WebAuthn/passkeys | auth-webauthn* |
| TOTP | auth-totp* |
| recovery codes | auth-recovery-code* |

Applications should migrate only after the required standalone packages have a
stable release.
