# Componenta Auth

Контракты аутентификации и PSR-7/PSR-15 компоненты для приложений Componenta на PHP 8.4+.

Пакет поддерживает password login, stateful sessions, remember-me cookie, подписанные JWT access-токены со stateful opaque refresh grants, OTP, magic links, password reset и lifecycle events.

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
- application adapters для используемых stores и delivery queues.

## Единственный идентификатор identity

Каждый authenticated subject является `Componenta\Identity\IdentityInterface`. Единственный идентификатор auth subject — UUID identity:

```php
$subjectId = $identity->uuid->toString();
```

Отдельного auth-specific ID больше нет. Session, remember-me, one-time tokens, refresh grants и JWT `sub` используют одну UUID-строку. Persistence adapter может сопоставлять UUID внутреннему PK, но это не является частью API auth-компонента.

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

`AuthenticatorFactory` сохраняет порядок и fail-fast отклоняет пустой список, дубли, отсутствующие services и значения неверного типа.

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
- повторно проверяет expiry перед удалением rows, выбранных bounded cleanup;
- ограничивает размеры batch и входных ID.

Metadata доступна через `$session->attributes`. `getAttribute()` различает отсутствующий ключ и явно записанный `null`.

`SessionCollection::pluck()` читает только объявленные свойства session либо metadata attributes и отклоняет неизвестные ключи.

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
    ],
],
```

Проверяются signature, точные profile values, `iat`, `nbf`, `exp` и максимальная lifetime access token. Signer записывает explicit `typ` header и не разрешает custom claims заменять registered claims.

Минимальный HMAC secret: 32/48/64 bytes для HS256/HS384/HS512.

Refresh token и family ID содержат 32–64 random bytes. `rotateAtomically()` остаётся storage-level security boundary. Store обязан вернуть именно запрошенный successor с ожидаемым expiry и active state.

Ответы с access/refresh credentials всегда получают `Cache-Control: no-store`, `Pragma: no-cache` и `Content-Type: application/json`.

## OTP и delivery queues

`CodeStoreInterface::verifyAndConsume()` объединяет attempts, expiry, verifier comparison и consume одной locked/versioned record. Expired и invalid outcomes различаются.

HTTP handlers внедряют `TokenRequestQueueInterface` или `OtpRequestQueueInterface` напрямую и ставят в очередь `TokenRequest`/`OtpRequest`. Пустые requester wrappers удалены.

User lookup, generation, persistence и sender I/O выполняют `TokenRequestProcessor`/`OtpRequestProcessor` вне HTTP request thread.

Встроенный SQL manager one-time tokens заменяет challenge субъекта одним atomic UPSERT. Поэтому таблица обязана иметь `UNIQUE` constraint на колонке canonical subject UUID. OTP stores остаются application adapters и должны атомарно реализовывать `verifyAndConsume()` над одной locked/versioned record.

## Password reset

`PasswordResetServiceInterface` владеет полной recovery transaction, включая проверку reset token и дорогое хэширование нового пароля. `PasswordResetResult::Success` означает: reset token consumed, password изменён, прежние session, remember-me и refresh credentials durably либо logically invalidated.

При разных stores необходимы credential version, transactional outbox и идемпотентный retry.

## События и публичные ошибки

Generic authentication events содержат тип payload, но не raw password, OTP, bearer или refresh token.

`DeniedReasonInterface::$attributes` является trusted audit context. Default response публикует только stable error code. Явно разрешённые scalar details предоставляются через `PublicDeniedReasonInterface::$publicDetails`.

## Input и cookie validation

Authentication inputs проверяются по типу и размеру до hash/provider/storage operations. `InvalidPayloadException` больше не удерживает credential payload.

`CookieTransport` валидирует cookie names, Path, Domain, SameSite, требования `__Secure-`/`__Host-` и размеры credentials. `SameSite=None` требует `Secure`.

## Основные ключи конфигурации

| Ключ | Назначение |
|---|---|
| `ConfigKey::AUTH` | Корень auth-конфигурации. |
| `ConfigKey::STRATEGIES` | Упорядоченные service IDs. |
| `ConfigKey::EVENTS` | Eventing decorator. |
| `ConfigKey::SESSION` | Session persistence и touch settings. |
| `ConfigKey::REMEMBER_ME` | Feature flag и settings remember-me; по умолчанию выключен. |
| `ConfigKey::JWT` | Явный JWT/refresh profile. |
| `ConfigKey::DENIED` | Mapping HTTP status. |
| `ConfigKey::LISTENERS` | Lifecycle listeners. |

## Миграция

`v2` содержит намеренные breaking security/API changes. См. [MIGRATION-v2.md](MIGRATION-v2.md). Нельзя имитировать `rotateAtomically()` или `verifyAndConsume()` последовательностью старых методов: это возвращает устранённые race conditions.
