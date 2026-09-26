# Componenta Auth 3

Transport-neutral контракты и orchestration аутентификации для приложений
Componenta на PHP 8.4+.

Auth 3 намеренно оставляет `componenta/auth` маленьким core. Конкретные
способы входа, HTTP, authentication sessions и persistence вынесены в отдельные
пакеты.

## Что остаётся в core

`componenta/auth` содержит:

- `AuthenticatorInterface` / `Authenticator`;
- упорядоченную цепочку `AuthenticationStrategyInterface`;
- immutable `ContextInterface` для данных конкретной попытки/request;
- `AuthenticationResult`;
- `AuthenticationEvidence`;
- `AuthenticationGuardInterface`;
- `AuthenticationStateInterface`;
- единый `IdentityProviderInterface` для поиска по canonical UUID;
- общие denial-типы и lifecycle events.

Core не зависит от PSR HTTP, Componenta DI, Cycle Database, password/JWT
библиотек и SDK провайдеров.

## Пакеты

Устанавливаются только нужные возможности:

- `componenta/auth-http` — PSR-7/15/17 transport и middleware.
- `componenta/auth-app` — invocation-only `#[CurrentUser]`.
- `componenta/auth-session` — модель и lifecycle authentication session.
- `componenta/auth-session-database` — persistence через Cycle Database.
- `componenta/auth-session-http` — browser session, pre-auth transport и CSRF, привязанный к generation сессии.
- `componenta/auth-session-app` — invocation-only `#[CurrentSession]`.

Password, OTP, remember-me, magic-link, password-reset, JWT, WebAuthn, TOTP и
recovery codes должны находиться в собственных capability-пакетах.

`componenta/session` не относится к authentication sessions и не является
зависимостью этой архитектуры.

## AuthenticationResult

Denial терминален по умолчанию. Мягкий отказ должен быть отмечен явно через
`continueOnFailure: true`.

Успешная аутентификация всегда обязана передавать явный evidence:

```php
return new AuthenticationResult(
    subject: $identity,
    evidence: new AuthenticationEvidence(
        methods: ['webauthn'],
        capabilities: ['user_verified', 'phishing_resistant'],
    ),
);
```

Auth 3 не выводит assurance из роли пользователя или одного названия метода.

Дополнительно result может содержать:

- один opaque `transportPayload`;
- один несекретный `AuthenticationStateInterface`, принадлежащий конкретному capability-пакету.

Универсального `artifacts[]`/result bag нет.

## Context

`Context` остаётся небольшим immutable carrier для request/attempt-scoped
данных. Через него HTTP слой может передать PSR request или transport state.

Repositories, logger и другие сервисы передаются через конструктор strategy.
`Context` не является service locator.

## Guards

`AuthenticationGuardInterface` нужен для fail-closed проверок, общих для всех
способов входа: например, blocked/deleted identity.

Guard — не authorization policy. Roles/permissions остаются ответственностью
приложения.

## Authentication sessions

`componenta/auth-session` разделяет:

- публичный `AuthSession::$uuid`;
- секретный `SessionCredential`.

Credential содержит 32 случайных байта в unpadded base64url и никогда не
используется как management identifier.

Browser login начинается с отдельной короткоживущей pre-auth transaction.
Pre-auth credential и request token потребляются один раз и никогда не
превращаются в authenticated session.

См. `MIGRATION-v3.md` для карты перехода с Auth 2.
