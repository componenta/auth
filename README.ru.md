# Componenta Auth

Контракты аутентификации и PSR-7/PSR-15 компоненты для Componenta-приложений на PHP 8.4+.

Пакет поддерживает вход по паролю, stateful sessions, remember-me cookie, подписанные JWT access-токены со stateful opaque refresh grants, OTP, magic links, сброс пароля и события жизненного цикла аутентификации. Механизм проверки credentials отделён от их жизненного цикла и записи в HTTP transport.

Для браузерных приложений рекомендуемый профиль — stateful `HttpOnly` session. JWT access-токены должны быть короткоживущими, а opaque refresh-токены — атомарно ротируемыми stateful grants.

## Установка

```bash
composer require componenta/auth
```

`Componenta\Auth\ConfigProvider` объявлен в `extra.componenta.config-providers`. При установленном `componenta/composer-plugin` провайдер может подключаться автоматически.

## Требования

- PHP 8.4 или новее;
- `ext-mbstring`;
- реализации PSR-7 / PSR-15 / PSR-17 для HTTP-слоя;
- Componenta DI 2 или 3;
- application adapters для используемых хранилищ.

## Явная композиция Authenticator

Порядок стратегий является частью security policy и задаётся явно:

```php
use Componenta\Auth\Http\Strategy\Jwt\JwtStrategy;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\SessionStrategy;

return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
            JwtStrategy::class,
        ],
        'events' => true,
    ],
];
```

`AuthenticatorFactory` сохраняет порядок и fail-fast отклоняет пустой список, дубли, отсутствующие сервисы и объекты, не реализующие `AuthenticationStrategyInterface`.

Ручная сборка в composition root также поддерживается:

```php
$authenticator = new Authenticator(
    $passwordStrategy,
    $sessionStrategy,
    $jwtStrategy,
);

$result = $authenticator->attempt($payload, new Context());
```

`Authenticator` пропускает неподдерживающие стратегии, возвращает первую успешную identity, последнюю причину отказа либо выбрасывает `NoStrategyFoundException`, если payload не поддержан ни одной стратегией.

## AuthenticationResult

| Свойство | Назначение |
|---|---|
| `$subject` | `IdentityInterface` при успехе или `DeniedReasonInterface` при отказе. |
| `$transportPayload` | Подготовленная стратегией mutation для response transport. |
| `$attributes` | Проверенное request-scoped состояние, например уже найденная `SessionInterface`. |

Отдельного boolean-флага успеха нет: успех представлен объектом `IdentityInterface`.

## Стратегии и HTTP extraction

Стратегия возвращает identity либо причину отказа. Обычные неверные credentials не являются исключением; исключения предназначены для некорректной конфигурации, malformed input и инфраструктурных ошибок.

Password и OTP extractors проверяют типы и размеры значений до нормализации, хэширования, provider lookup и обращения к storage. Поле `remember` принимает только boolean, `0/1` и разрешённые текстовые значения. `InvalidPayloadMiddleware` преобразует `InvalidPayloadException` в HTTP 400.

## Детерминированная запись credentials

`AuthenticationMiddleware` создаёт request-scoped `CredentialTransportState`, передаёт состояние downstream handler и один раз применяет итоговые mutations после его завершения.

`CredentialTransportState::clear()` терминален: удаление credentials всегда сильнее уже подготовленной или будущей ротации. Поэтому remember-me recovery или обновление session chain не могут повторно установить cookie после logout.

Custom handler может получить `CredentialTransportState::class` из request attributes и вызвать `clear()` при окончательном удалении credentials.

## Sessions

Session subsystem включает генерацию ID, idle/absolute expiration, ограниченную replacement chain, транзакционную регенерацию и lifecycle events.

`SessionStrategy` и `RememberMeStrategy` передают уже проверенную `SessionInterface` через `AuthenticationResult::$attributes`. `TouchSessionMiddleware` использует её без второго SELECT.

UPDATE активности ограничен `auth.session.touchInterval` — по умолчанию 60 секунд. `SessionManagerInterface::cleanup(int $limit)` удаляет только ограниченный batch. `SessionGarbageCollectionMiddleware` лишь ставит работу в `SessionCleanupSchedulerInterface`, не выполняя unbounded DELETE внутри HTTP request.

## Remember-me

Remember-me credentials генерируются как случайные opaque tokens и хранятся в SHA-256 representation. Consume имеет одного победителя благодаря проверке affected rows.

Termination/regeneration listeners подключены конфигурацией пакета и являются critical synchronous participants. Ошибка revoke больше не скрывается за формально успешным завершением session. Для группы sessions используется один `revokeForSessions()` вместо N отдельных DELETE.

## JWT и refresh grants

JWT используется как короткоживущий подписанный access credential. Opaque refresh token остаётся stateful grant.

`RefreshTokenStoreInterface` требует:

- `storeInitial()` для первого token family;
- `rotateAtomically()` для lookup, проверки expiry, revoke, создания successor и replay compromise в одном serialized transition;
- `revoke()` и `revokeAllForUser()` для явной и account-wide invalidation.

Store обязан иметь durable family/grant state. После replay в family не должно оставаться active descendants, а конкурентная transaction не должна вставить новый active token после compromise.

Ответы с access/refresh tokens всегда получают:

```text
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
```

Если после ротации subject больше не существует, созданный successor немедленно отзывается.

## OTP

`CodeStoreInterface::verifyAndConsume()` объединяет attempts, expiry, сравнение verifier и consume одной locked/versioned challenge record. Нельзя реализовывать его последовательностью старых независимых методов.

Для короткого OTP production storage рекомендуется хранить keyed verifier, например HMAC, а не canonical code, если backing store может быть прочитан отдельно.

## Magic links, OTP delivery и password reset

HTTP request path только ставит opaque work в `TokenRequestQueueInterface` или `OtpRequestQueueInterface`. Lookup пользователя, создание token/code, persistence и sender I/O выполняют `TokenRequestProcessor` / `OtpRequestProcessor` в worker. Для существующего и неизвестного аккаунта request-thread выполняет одинаковую работу.

`PasswordResetServiceInterface` владеет полной security transaction. `PasswordResetResult::Success` означает: reset token consumed, password изменён, прежние sessions, remember-me credentials и refresh grants инвалидированы.

При разных stores используйте credential version, transactional outbox и идемпотентный retry вместо частично успешного reset.

## События и публичные ошибки

`EventingAuthenticator` передаёт в generic events только тип payload, но не raw password, OTP, bearer или refresh token.

`CriticalEventListenerInterface` обозначает fail-closed security participant. Ошибки обычных observers — metrics, notifications — по-прежнему изолируются.

`DeniedReasonInterface::$attributes` является внутренним audit context. Default `DeniedResponseFactory` публикует только стабильный `error`. Публичные детали требуют явного `PublicDeniedReasonInterface`.

## HTTP middleware

Пакет предоставляет:

- `InvalidPayloadMiddleware`;
- `AuthenticationMiddleware`;
- `RequireAuthenticationMiddleware`;
- `TouchSessionMiddleware`;
- `SessionGarbageCollectionMiddleware`.

Структуру routes, CSRF protection и endpoint-specific rate limiting определяет приложение.

## Основные ключи конфигурации

| Ключ | Назначение |
|---|---|
| `ConfigKey::AUTH` | Корень auth-конфигурации. |
| `ConfigKey::STRATEGIES` | Упорядоченные service IDs стратегий. |
| `ConfigKey::EVENTS` | Включение eventing decorator. |
| `ConfigKey::SESSION` | Session storage и touch settings. |
| `ConfigKey::REMEMBER_ME` | Remember-me persistence и cookie settings. |
| `ConfigKey::JWT` | JWT/refresh TTL и claims. |
| `ConfigKey::MAGIC_LINK` | Magic-link integration. |
| `ConfigKey::PASSWORD_RESET` | Password-reset integration. |
| `ConfigKey::DENIED` | Mapping HTTP-ответов при отказе. |
| `ConfigKey::LISTENERS` | Auth event listener services. |

## Миграция

В `v2` намеренно изменены security-critical contracts. Обновите adapters и composition по [MIGRATION-v2.md](MIGRATION-v2.md). Не имитируйте `rotateAtomically()` или `verifyAndConsume()` последовательными вызовами старых методов: это сохраняет устраняемые race conditions.
