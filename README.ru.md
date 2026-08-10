# Componenta Auth

Контракты и HTTP-компоненты аутентификации для Componenta-приложений на PHP 8.4+.

Безопасный профиль для браузера — stateful HttpOnly session. JWT access-токены должны быть короткоживущими, а opaque refresh-токены остаются stateful grants с атомарной ротацией и обнаружением повторного использования.

## Установка

```bash
composer require componenta/auth
```

Требуются `ext-mbstring`, PSR-7/15/17 и storage adapters для включённых механизмов.

## Явная композиция

Порядок стратегий является частью security policy и задаётся явно:

```php
return [
    'auth' => [
        'strategies' => [
            SessionStrategy::class,
            RememberMeStrategy::class,
        ],
        'events' => true,
    ],
];
```

`AuthenticatorFactory` отклоняет пустой список, дубли, отсутствующие сервисы и объекты неверного типа. Поддерживаются Componenta DI 2 и 3.

## Инварианты жизненного цикла credentials

- Очистка credentials терминальна для запроса: logout нельзя перезаписать отложенной ротацией cookie.
- Remember-me listeners включены по умолчанию и работают fail-closed.
- Refresh rotation выполняется одной атомарной storage-операцией с durable family compromise.
- OTP attempts, comparison и consume относятся к одной locked/versioned записи.
- Успешный password reset инвалидирует все прежние долгоживущие credentials.
- Generic auth events не содержат пароли, OTP, bearer и refresh tokens.
- Ответы с токенами имеют `no-store` и `no-cache`.

## Производительность sessions

Проверенная `SessionInterface` передаётся через `AuthenticationResult::$attributes`, поэтому `TouchSessionMiddleware` не делает повторный lookup. Частота UPDATE ограничивается `auth.session.touchInterval` (по умолчанию 60 секунд). Очистка истёкших sessions выполняется ограниченными batch-операциями вне HTTP request path.

## Обязательные application adapters

Приложение реализует `RefreshTokenStoreInterface`, `CodeStoreInterface::verifyAndConsume()`, `PasswordResetServiceInterface`, очереди `TokenRequestQueueInterface` / `OtpRequestQueueInterface` и `SessionCleanupSchedulerInterface`.

Полный список breaking changes приведён в [MIGRATION-v2.md](MIGRATION-v2.md).

`DeniedReasonInterface::$attributes` считается внутренним audit context. Default HTTP response содержит только стабильный `error`; публичные детали требуют явного `PublicDeniedReasonInterface`.
