# Componenta Auth

Контракты аутентификации и PSR-7/PSR-15 компоненты для приложений Componenta на PHP 8.4+.

Пакет поддерживает password login, stateful sessions, remember-me cookie, подписанные JWT access-токены со stateful opaque refresh grants, OTP, magic links, password reset и authentication lifecycle events.

Для браузерных приложений рекомендуемый профиль — stateful `HttpOnly` session. JWT access token должен быть короткоживущим, а opaque refresh token остаётся серверным grant с атомарной ротацией и обнаружением replay.

## Установка

```bash
composer require componenta/auth
```

`Componenta\Auth\ConfigProvider` объявлен в `extra.componenta.config-providers`.

## Требования

- PHP 8.4 или новее;
- `ext-mbstring`;
- реализации PSR-7, PSR-15 и PSR-17;
- Componenta DI 2 или 3;
- Cycle Database для встроенных session, remember-me, one-time, refresh и OTP stores;
- application adapters для delivery queues, password reset и stores, которые приложение намеренно переопределяет.

## Единственный идентификатор identity

Каждый authenticated subject является `Componenta\Identity\IdentityInterface`. Единственный идентификатор auth subject — UUID identity:

```php
$subjectId = $identity->uuid->toString();
```

Отдельного auth-specific ID больше нет. Session, remember-me, one-time tokens, OTP challenges, refresh grants и JWT `sub` используют одну UUID-строку. Persistence adapter может сопоставлять UUID внутреннему PK, но это не является частью API auth-компонента.

## Явная композиция Authenticator

Порядок стратегий является частью security policy и задаётся явно:

```php
return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
            PasswordStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
        'rememberMe' => [
            'enabled' => true,
        ],
    ],
];
```

`AuthenticatorFactory` сохраняет порядок и fail-fast отклоняет пустой список, дубли, отсутствующие services и значения неверного типа. Встроенный `RememberMeStrategy` дополнительно запрещён при `auth.rememberMe.enabled=false`, потому что эта стратегия требует активных critical termination/regeneration listeners.

Password, OTP и magic-link verification handlers используют тот же `AuthenticatorInterface`; они больше не обходят общий event decorator прямым вызовом отдельной strategy.

## AuthenticationResult

Результат содержит только типизированное состояние:

| Свойство | Назначение |
|---|---|
| `$subject` | `IdentityInterface` при успехе либо `DeniedReasonInterface`. |
| `$transportPayload` | Optional mutation response transport. |
| `$session` | Проверенная request-local `SessionInterface`. |

Открытый `array $attributes` удалён. Request-local session state больше не записывается в identity entity, что исключает его протекание через ORM identity map или singleton provider в long-running worker.

## Property-oriented API PHP 8.4

Состояние доступно через свойства:

```php
$context->attributes;
$session->attributes;
$sessions->empty;
$transportState->empty;
$transportState->cleared;
$transportState->payloads;
$refreshToken->revoked;
```

Методы сохраняются для действий и операций с аргументами: `getAttribute($name, $default)`, `find($id)`, `consume($token)`, `isExpired($now)`, `queue()` и `clear()`.

## Детерминированная запись credentials

`AuthenticationMiddleware` создаёт один request-scoped `CredentialTransportState` и применяет итоговое решение один раз после downstream handler.

`clear()` терминален: удаление всегда сильнее уже подготовленной или будущей ротации. При наличии terminal middleware `LogoutHandler` только отмечает clear и не удаляет те же cookies повторно.

## Sessions

`SessionStrategy` и `RememberMeStrategy` возвращают уже проверенную session через `AuthenticationResult::$session`. `TouchSessionMiddleware` использует её без второго SELECT.

Session manager:

- проверяет idle и absolute expiry перед touch;
- ограничивает частоту UPDATE через `auth.session.touchInterval`;
- использует conditional UPDATE;
- сохраняет transaction + optimistic claim при regeneration;
- выполняет critical lifecycle participants внутри DB transaction, а best-effort observers — только после commit;
- повторно проверяет expiry перед удалением rows, выбранных bounded cleanup;
- ограничивает размеры batch и входных ID.

Metadata доступна через `$session->attributes`. `getAttribute()` различает отсутствующий ключ и явно записанный `null`.

`SessionCollection::pluck()` читает только объявленные свойства session либо metadata attributes и отклоняет неизвестные ключи.

## Primary reads для credential state

Cycle Database может использовать отдельные READ и WRITE drivers. Replica lag недопустим для состояния аутентификации: удалённая на primary session не должна оставаться действительной только потому, что read replica ещё содержит старую строку.

Поэтому встроенные session, remember-me, one-time-token, refresh и OTP stores принудительно читают security state через `DatabaseInterface::WRITE`. Read replica допустима только для неавторитетной housekeeping-выборки, если последующая write-операция повторно проверяет security predicate на primary.

Custom credential store обязан сохранить это правило либо предоставить эквивалентную linearizable consistency guarantee.

## Remember-me

Remember-me выключен по умолчанию. Когда `auth.rememberMe.enabled` равен `true`, пакет автоматически добавляет обязательные termination/regeneration listeners; оба являются critical lifecycle participants.

Remember-me token — 256-bit opaque credential, хранящийся как SHA-256 representation. Consume остаётся single-winner через affected rows. Bulk termination использует `revokeForSessions()` с chunking. Revoke-all-except удаляет и rows с `NULL session_id`.

Housekeeping выполняется bounded методом `cleanup(int $limit): int` из worker/scheduler.

## Password authentication

Password provider получает только нормализованную identity-строку, а не payload с submitted password:

```php
public function findByIdentity(
    string $identity,
): null|(IdentityInterface&PasswordAwareInterface);
```

Пароль доступен только verifier. Dummy hash создаётся при construction/warm-up.

## JWT и refresh grants

JWT validation является явным профилем. `issuer`, `audience` и token `type` обязательны; clock skew ограничен:

```php
'auth' => [
    'jwt' => [
        'issuer' => 'https://issuer.example',
        'audience' => 'componenta-api',
        'type' => 'at+jwt',
        'accessTtl' => 900,
        'refreshTtl' => 604800,
        'clockSkew' => 30,
        'refreshStore' => [
            'tokenTable' => 'refresh_tokens',
            'familyTable' => 'refresh_token_families',
        ],
    ],
],
```

Проверяются signature, точные profile values, `iat`, `nbf`, `exp` и максимальная lifetime access token. Signer записывает explicit `typ` header и не разрешает custom claims заменять registered claims.

Минимальный HMAC secret: 32/48/64 bytes для HS256/HS384/HS512.

Refresh token и family ID содержат 32–64 random bytes. Default binding `RefreshTokenStoreInterface` — `DatabaseRefreshTokenStore`.

Встроенный refresh store:

- сохраняет только SHA-256 representation bearer token ID;
- использует отдельную family-row как serialization point для rotation, replay handling и bulk revocation;
- выполняет consume presented token и создание successor в одной DB transaction;
- откатывает claim старого token, если insert successor завершился ошибкой;
- хранит обычный revoke family отдельно от replay compromise, поэтому password reset/logout-all не маскируются под атаку;
- при реальном replay помечает family как compromised и отзывает все активные descendants;
- читает security state только с primary/write connection.

Минимальные требования к schema:

```text
refresh_token_families
  family_id       PRIMARY KEY или UNIQUE
  user_id         NOT NULL, index
  revoked_at      nullable
  compromised_at  nullable
  lock_nonce      NOT NULL

refresh_tokens
  token_hash      PRIMARY KEY или UNIQUE
  family_id       NOT NULL, index/FK -> refresh_token_families.family_id
  user_id         NOT NULL, index
  expires_at      NOT NULL
  consumed_at     nullable
  revoked_at      nullable
```

Названия таблиц и колонок настраиваются. `token_hash` содержит 64-символьный SHA-256 hex, а не bearer token. `familyRevokedAt` и `compromisedAt` являются отдельными настраиваемыми состояниями family, даже если token table также использует колонку `revoked_at`.

`RefreshTokenStoreInterface::rotateAtomically()` остаётся security contract для custom implementations. Custom store обязан обеспечить эквивалентную сериализацию family и replay semantics.

Ответы с access/refresh credentials всегда получают `Cache-Control: no-store`, `Pragma: no-cache` и `Content-Type: application/json`.

## OTP и delivery queues

`CodeStoreInterface::verifyAndConsume()` объединяет attempt accounting, expiry, verifier comparison и consume над одной versioned challenge.

Default binding `CodeStoreInterface` — `DatabaseCodeStore`. Plain OTP в БД не хранится. Вместо него используется `HMAC-SHA-256(destination || NUL || code)` с отдельным application secret:

```php
'auth' => [
    'otp' => [
        'hmacKey' => $_ENV['AUTH_OTP_HMAC_KEY'], // минимум 32 bytes
        'store' => [
            'table' => 'otp_codes',
        ],
    ],
],
```

Пустой default `auth.otp.hmacKey` намеренно неработоспособен: built-in SQL store fail-fast не создаётся, пока приложение не передаст secret длиной минимум 32 bytes. Не переиспользуйте JWT signing key.

`DatabaseCodeStore` использует random `challenge_id` как optimistic version. UPDATE attempts и DELETE при success/expiry включают эту версию. Если challenge заменяется во время verification, stale operation завершается как invalid и не списывает попытку у replacement и не consume его.

Schema должна гарантировать один текущий challenge на destination:

```text
otp_codes
  destination   PRIMARY KEY или UNIQUE
  user_id       NOT NULL
  challenge_id  NOT NULL
  verifier      NOT NULL
  expires_at    NOT NULL
  attempts      NOT NULL
```

Встроенный SQL manager one-time tokens для magic links/password-reset delivery заменяет challenge субъекта одним atomic UPSERT. Поэтому таблица обязана иметь `UNIQUE` constraint на canonical subject UUID.

HTTP handlers внедряют `TokenRequestQueueInterface` или `OtpRequestQueueInterface` напрямую и ставят в очередь `TokenRequest`/`OtpRequest`. User lookup, generation, persistence и sender I/O выполняют `TokenRequestProcessor`/`OtpRequestProcessor` вне HTTP request thread.

Custom `CodeStoreInterface` обязан сохранить single-winner, atomic attempt accounting, isolation replacement challenge и primary-read semantics.

## Password reset

`PasswordResetServiceInterface` владеет полной recovery transition, включая проверку reset token и дорогое хэширование нового пароля. `PasswordResetResult::Success` означает: reset token consumed, password изменён, прежние session, remember-me и refresh credentials durably либо logically invalidated.

Пакет не может создать общую транзакцию вокруг application-owned password repository. Если password state и credentials находятся в разных stores, необходимы credential version, transactional outbox и идемпотентный retry вместо сообщения об успехе после частичного изменения.

## События и публичные ошибки

Generic authentication events содержат тип payload, но не raw password, OTP, bearer или refresh token.

Critical session lifecycle listeners выполняются до best-effort observers. Для DB-backed session transitions critical listeners входят в transaction, а observers видят event только после commit.

`DeniedReasonInterface::$attributes` является trusted audit context. Встроенный `DeniedResponseFactory` всегда публикует только stable error code. Если приложению нужны дополнительные client-facing поля ошибки, оно должно предоставить собственную реализацию `DeniedResponseFactoryInterface`; базовый пакет никогда не сериализует audit attributes.

## Input и cookie validation

Authentication inputs проверяются по типу и размеру до hash/provider/storage operations. `InvalidPayloadException` больше не удерживает credential payload.

Built-in HTTP handlers со strict extractors должны находиться за `InvalidPayloadMiddleware` либо application-level mapper, который преобразует `InvalidPayloadException` в стабильный HTTP 400. Без такого mapper malformed request зависит от глобального exception handler и не является поддерживаемой production composition.

`CookieTransport` валидирует cookie names, Path, Domain, SameSite, требования `__Secure-`/`__Host-` и размеры credentials. `SameSite=None` требует `Secure`.

## Основные ключи конфигурации

| Ключ | Назначение |
|---|---|
| `ConfigKey::AUTH` | Корень auth-конфигурации. |
| `ConfigKey::STRATEGIES` | Упорядоченные service IDs. |
| `ConfigKey::EVENTS` | Eventing decorator. |
| `ConfigKey::SESSION` | Session persistence и touch settings. |
| `ConfigKey::REMEMBER_ME` | Feature flag и settings remember-me; по умолчанию выключен. |
| `ConfigKey::OTP` | OTP store settings и отдельный HMAC verifier key. |
| `ConfigKey::JWT` | JWT profile и settings встроенного refresh store. |
| `ConfigKey::DENIED` | Mapping HTTP status. |
| `ConfigKey::LISTENERS` | Lifecycle listeners. |

## Миграция

`v2` содержит намеренные breaking security/API changes. См. [MIGRATION-v2.md](MIGRATION-v2.md). Нельзя имитировать `rotateAtomically()` или `verifyAndConsume()` последовательностью старых методов: это возвращает устранённые race conditions.

Если Cycle Database использует отдельный READ driver, все credential-state consumers должны быть обновлены вместе с пакетом: `v2` намеренно читает auth state через primary/write driver, чтобы replica lag не мог «воскресить» отозванный credential.
