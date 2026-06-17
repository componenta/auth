# Componenta Auth

Пакет аутентификации для Componenta-приложений. Он помогает проверить, кто делает запрос: по паролю, bearer/JWT-токену, сессии, remember-me cookie, OTP-коду, magic-link или токену сброса пароля.

Пакет не решает, какие действия пользователю разрешены. Проверка прав находится в `componenta/policy`. `componenta/auth` только устанавливает личность пользователя или возвращает причину отказа входа.

## Установка

```bash
composer require componenta/auth
```

Пакет объявляет `Componenta\Auth\ConfigProvider` в `extra.componenta.config-providers`.
Если установлен `componenta/composer-plugin`, провайдер автоматически добавляется в сгенерированный список провайдеров.

## Требования

- PHP 8.4+
- PSR-7 / PSR-15, если используются HTTP-промежуточные обработчики
- хранилище для включённых механизмов входа: сессии, remember-me токены, refresh-токены, OTP-коды или токены сброса пароля

## Связанные пакеты

| Пакет | Зачем нужен здесь |
|---|---|
| `componenta/session` | Хранит состояние браузерной сессии и идентификатор сессии. Нужен для сессионной аутентификации. |
| `componenta/app-http` | Подключает промежуточные обработчики аутентификации в HTTP-приложениях, которые используют PSR-7 запросы и PSR-15 промежуточные обработчики. |
| `componenta/event` | Нужен, если приложение хочет реагировать на вход, отказ, logout, обновление сессии или завершение всех сессий. |
| `componenta/policy` | Использует найденного пользователя как актора для проверки прав. |
| `componenta/di` | Создаёт стратегии входа, менеджеры токенов, промежуточные обработчики и слушателей через контейнер. |

## Основной поток

```php
use Componenta\Auth\Authenticator;
use Componenta\Auth\Context;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Identity\IdentityInterface;

$authenticator = new Authenticator(
    $passwordStrategy,
    $jwtStrategy,
    $sessionStrategy,
);

$result = $authenticator->attempt($payload, new Context());

if ($result->subject instanceof IdentityInterface) {
    $identity = $result->subject;
}

if ($result->subject instanceof DeniedReasonInterface) {
    $reason = $result->subject;
}
```

`Authenticator` перебирает зарегистрированные стратегии по порядку:

1. стратегия говорит, поддерживает ли она переданный объект входа;
2. неподдерживаемые стратегии пропускаются;
3. поддерживающие стратегии выполняются по очереди;
4. первая успешная стратегия возвращает `IdentityInterface`;
5. если все поддерживающие стратегии отказали, возвращается последняя причина отказа;
6. если объект входа не поддержала ни одна стратегия, выбрасывается `NoStrategyFoundException`.

`AuthenticationResult` содержит два публичных свойства:

| Свойство | Значение |
|---|---|
| `$subject` | Успешный `IdentityInterface` или причина отказа `DeniedReasonInterface`. |
| `$transportPayload` | Необязательный объект, который нужно записать в ответ, например обновлённую сессию или remember-me cookie. |

Отдельного boolean-флага успеха нет. Успех определяется проверкой, что `$result->subject` реализует `IdentityInterface`.

## Стратегия входа

```php
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;

final readonly class ApiKeyStrategy implements AuthenticationStrategyInterface
{
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof ApiKeyPayload;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        // Верните AuthenticationResult с IdentityInterface при успехе
        // или DeniedReasonInterface при отказе.
    }
}
```

Стратегия должна быть предсказуемой для одного объекта входа и одного контекста. Обычный отказ входа не должен быть исключением: возвращайте результат с `DeniedReasonInterface`.

## Объекты входа и HTTP

Стратегия не обязана знать, откуда пришли данные. HTTP-слой отдельно читает PSR-7 запрос и создаёт объект входа:

- bearer-токен из `Authorization: Bearer ...`;
- логин и пароль из формы или JSON-тела;
- идентификатор сессии из cookie;
- OTP-код;
- magic-link токен;
- токен сброса пароля.

Так стратегии можно тестировать без HTTP-запроса, а приложение может менять форму запроса без переписывания логики входа.

## Сессии

Сессионная аутентификация используется, когда браузер уже хранит идентификатор сессии, а приложение может связать эту сессию с пользователем.

```php
$result = $sessionStrategy->attempt($sessionPayload, $context);
```

Сессионная часть включает коллекцию сессий, атрибуты сессии, генерацию id, определение устройства и управление сессиями в хранилище.

## Токены

Пакет содержит инфраструктуру для:

- JWT access-токенов и refresh-токенов;
- сценариев запроса и проверки OTP;
- сценариев запроса и проверки magic-link;
- токенов сброса пароля;
- remember-me токенов.

Менеджеры токенов отвечают за хранение и инвалидирование. Обработчики токенов отвечают за подпись, разбор и причины отказа: истёк, некорректен, уже использован или скомпрометирован.

## События

`EventingAuthenticator` оборачивает попытки входа событиями:

- `AuthenticationAttempted`
- `AuthenticationSucceeded`
- `AuthenticationDenied`
- `LoggedOut`
- `SessionRegenerated`
- `SessionsTerminated`
- `AllSessionsTerminated`

Слушатели находятся через `EventListenerProviderInterface`. Используйте события для audit log, очистки сессий, ротации remember-me токенов, уведомлений и метрик.

## HTTP-промежуточные обработчики

HTTP-слой предоставляет:

- `AuthenticationMiddleware`: выполняет попытку входа и прикрепляет состояние аутентификации к запросу или контексту;
- `RequireAuthenticationMiddleware`: отклоняет запросы без пользователя;
- `TouchSessionMiddleware`: обновляет активность сессии;
- `SessionGarbageCollectionMiddleware`: запускает очистку хранилища сессий.

Пакет не задаёт структуру маршрутов. Приложение само решает, какие маршруты публичные, а какие требуют пользователя.

`AuthenticationMiddleware` записывает результат в атрибуты PSR-7 запроса:

| Ключ атрибута | Значение |
|---|---|
| `Componenta\Identity\IdentityInterface::class` | Есть, если аутентификация успешна. |
| `Componenta\Auth\DeniedReasonInterface::class` | Есть, если подходящая стратегия отказала запросу. |

Если стратегия вернула `$transportPayload`, промежуточный обработчик требует `PayloadStorageInterface`. Без него будет выброшен `LogicException`, потому что пакет не сможет записать cookie или другие транспортные данные в ответ.

## Регистрация в контейнере

`ConfigProvider` регистрирует фабрики, псевдонимы, слушателей, обработчики токенов, менеджеры сессий и промежуточные обработчики. Активны только те стратегии и хранилища, которые подключило приложение.

Основные ключи конфигурации находятся в `ConfigKey`:

| Ключ | Назначение |
|---|---|
| `ConfigKey::AUTH` | Корневая конфигурация аутентификации. |
| `ConfigKey::STRATEGIES` | Упорядоченный список стратегий входа. |
| `ConfigKey::SESSION` | Настройки session-аутентификации и менеджера сессий. |
| `ConfigKey::REMEMBER_ME` | Настройки remember-me токенов. |
| `ConfigKey::JWT` | Настройки JWT access/refresh токенов. |
| `ConfigKey::MAGIC_LINK` | Настройки запроса и проверки magic-link. |
| `ConfigKey::PASSWORD_RESET` | Настройки токенов сброса пароля. |
| `ConfigKey::DENIED` | Фабрика HTTP-ответа при отказе входа. |
| `ConfigKey::LISTENERS` | Слушатели событий аутентификации. |

## Ошибки

Обычный отказ входа представлен `DeniedReasonInterface`, а не исключением. Исключения используются для ошибок инфраструктуры и программирования: неподдерживаемый объект входа, некорректное извлечение данных из запроса, отказ хранилища, неверная настройка токена или ошибка транспорта.
