# Componenta Auth

Контракты аутентификации и PSR-7/PSR-15 компоненты для приложений Componenta на PHP 8.4+.

Пакет поддерживает password login, stateful sessions, remember-me, JWT access/opaque refresh tokens, OTP, magic links, password reset и lifecycle events.

## Требования

- PHP 8.4+;
- `ext-ctype`, `ext-filter`, `ext-mbstring`;
- реализации PSR-7/15/17/20;
- Componenta DI 4;
- Cycle Database для встроенных SQL stores.

## Единая identity

Единственный публичный идентификатор субъекта — `IdentityInterface::$uuid`. Session, remember-me, one-time tokens, OTP, refresh grants и JWT `sub` используют этот UUID. Auth-specific ID и mutable `currentSessionId` отсутствуют.

## Authenticator

Порядок strategies задаётся явно. Для middleware-oriented chain remember-me следует подключать через `CompensatingRememberMeStrategy::class`, а не через raw `RememberMeStrategy::class`. `AuthenticatorFactory` намеренно отклоняет raw strategy: после успешной rotation queued response credential может быть отменён более поздним denial/UUID conflict/login replacement/exception, и в таком случае successor grant и непубликованная session должны быть компенсированы. Raw `RememberMeStrategy` остаётся low-level primitive для прямого вызова, когда caller сам владеет публикацией и rollback результата.

Denial **терминален по умолчанию**. Продолжение chain разрешается только через явный `AuthenticationResult(..., continueOnFailure: true)` для мягких отказов, например invalid session при наличии remember-me credential в том же request. Таким образом `RateLimited`, `UserDisabled` и другие security denials нельзя обойти более поздней strategy только из-за совпадения payload type.

`AuthenticationResult` fail-closed: denial не может содержать session или credential mutation; success не может продолжать chain; session обязана принадлежать возвращённой identity.

## Request-scoped transport

Вложенные `AuthenticationMiddleware` используют один `CredentialTransportState`, но каждая queued mutation сохраняет свой `PayloadStorageInterface`. Поэтому разные nested transports не применяют чужие credentials.

`clear()` терминален и очищает все зарегистрированные transports. Если успешная authentication требует response credential, но storage не настроен, middleware падает **до** downstream application handler.

Explicit password и OTP session login полностью заменяют старое browser auth-state. Public magic-link session verifier принимает только `ReplacingPayloadStorage`, поэтому direct construction не может случайно сохранить или повторно применить credential прежнего principal; стандартная Componenta factory подставляет wrapper автоматически.

Текущая session живёт в request attribute `SessionInterface::class`, а не в identity.

`LogoutHandler` рассчитан на выполнение **после `AuthenticationMiddleware`**. Server-side termination использует уже аутентифицированный request attribute `SessionInterface::class`. Если вызвать logout handler отдельно, он может удалить client-side credential, но не может безопасно угадать, какую неаутентифицированную server-side session row следует завершить.

## Sessions

`DatabaseSessionManager` читает security state только с primary/write connection, проверяет idle/absolute expiry, throttles touch, регенерирует session транзакционно и сразу инвалидирует старый ID. Старый ID никогда не разрешается в successor. Termination сериализуется с regeneration и удаляет уже созданную replacement lineage, поэтому конкурентный logout не оставляет активный successor. Subject-wide `terminateAll()` также сериализуется с regeneration: конкурентная ротация session не может пережить массовое завершение sessions пользователя. Critical lifecycle listeners выполняются внутри owning transition, observers — после commit.

Session timestamps всегда UTC и используют внутренний фиксированный формат `Y-m-d H:i:s`; это больше не пользовательская настройка.

Встроенная session table является credential-bearing storage: live session IDs должны оставаться восстанавливаемыми, потому что публичный session-management API умеет перечислять sessions, а persistence model отслеживает replacement lineage. Session DTO скрывают ID в debug/JSON, но доступ к таблице и логам БД всё равно должен быть ограничен. Хэширование существующего `id` column «на месте» несовместимо с текущим enumeration/lineage contract и поэтому не позиционируется как безопасный drop-in change.

## Remember-me

Remember-me выключен по умолчанию. При включении автоматически подключаются critical termination/regeneration listeners.

В v2 используется **стабильная grant-row с ротацией bearer**, а не delete-on-consume. Основной контракт:

```php
create(UuidInterface $subjectId, string $sessionId): string;
rotate(string $plainToken): RememberMeRotation|RememberMeCompromise|null;
bindRotation(RememberMeRotation $rotation, string $newSessionId): bool;
```

Grant хранит текущий `session_id` и `previous_session_id`. Logout/revoke совпадает по обоим значениям. Поэтому конкурентный logout не может пропустить уже начатую ротацию и оставить новый persistent credential.

При работе через `AuthenticationMiddleware` используется `CompensatingRememberMeStrategy`. Она делегирует authentication raw strategy, но после успешного bind регистрирует request-scoped compensation. Если более поздний terminal denial, UUID conflict, explicit login replacement, missing storage или downstream exception отменяет queued replacement credential, successor remember bearer отзывается, а непубликованная session завершается. После успешного `CredentialTransportState::apply()` callback удаляется и доставленный credential не отзывается.

Минимальная schema:

```text
remember_me_tokens
  id                   PRIMARY KEY
  user_id              NOT NULL, index
  token                UNIQUE NOT NULL   # стабильный selector
  verifier             NOT NULL          # SHA-256 текущего validator
  session_id           NOT NULL, index
  previous_session_id  nullable, index
  expires_at           NOT NULL
  created_at           NOT NULL
```

## OTP

`OtpConfig` задаёт реальный protocol profile: 6-18 цифр, TTL не более 600 секунд и ограничение attempts. `OtpExtractor` принимает **ровно configured length** до обращения к store.

`DatabaseCodeStore` хранит HMAC-SHA-256 verifier с отдельным ключом >=32 bytes и использует `challenge_id` как optimistic version. Verify/attempt accounting/consume являются одной challenge-version transition: правильный код, конкурирующий с последней неудачной попыткой, не может аутентифицироваться после достижения `maxAttempts`.

Все отрицательные публичные **responses** OTP verification схлопываются в `invalid_code`. `expired`/`too_many_attempts` остаются внутренними состояниями store и не сериализуются наружу, иначе endpoint становился бы прямым oracle существования account/challenge.

Это гарантия одинаковой публичной response-семантики, а не утверждение, что разные SQL states имеют абсолютно одинаковую end-to-end latency. DB miss и failed-attempt CAS объективно могут выполнять разный объём работы. Пакет поэтому не добавляет blocking `sleep()` или дорогой dummy hashing: такая «защита» сама создала бы request-amplification/DoS primitive. Production adapters `OtpRequestQueueInterface` должны быть durable/non-inline, если важна uniform account-existence request latency; request/verify endpoints всё равно требуют application-level rate limiting.

`OtpRequest` содержит одно значение identity/destination. Built-in processor не может найти одну identity и отправить code на произвольный другой destination. Альтернативный routing должен проверяться application adapter до enqueue.

Отдельный account/destination rate limiter обязателен; `maxAttempts` защищает только один challenge.

## One-time tokens и purpose

`TokenConfig` требует `purpose`:

```php
new TokenConfig('magic_link_tokens', 'magic_link');
new TokenConfig('password_reset_tokens', 'password_reset');
```

Stored representation domain-separated:

```text
SHA-256(purpose || NUL || bearer)
```

Поэтому token одного flow не принимается другим manager даже при ошибочно общей таблице.

`TokenRequest` содержит lookup/delivery identity, обязательный machine-readable `purpose` и optional non-sensitive context; отдельного untrusted destination нет. Context keys ограничены machine-readable identifiers, значения ограничены 4096 bytes и не допускают control characters до передачи queue adapter или sender, который строит URL. `TokenRequestQueueInterface` — durable multi-purpose queue boundary: adapter обязан сохранить и маршрутизировать `purpose`, а purpose-bound `TokenRequestProcessor` отклоняет ошибочно маршрутизированное сообщение до provider lookup, token generation и delivery. Production adapter не должен выполнять provider lookup/delivery inline, если важна uniform account-existence request latency.

Magic-link consuming endpoints принимают только POST с token в parsed body.
GET возвращает 405 с Allow: POST и не вызывает authentication, поэтому
prefetch почтового клиента или link scanner не может погасить credential.
Ответы остаются non-cacheable и используют Referrer-Policy: no-referrer.

## JWT и refresh

JWT profile явно задаёт issuer/audience/type; проверяются signature, `iat`, optional `nbf`, `exp`, skew и максимальная lifetime. Registered claims нельзя заменить custom claims. HMAC minimum: 32/48/64 bytes для HS256/384/512.

`DatabaseRefreshTokenStore` хранит только SHA-256 bearer representations, сериализует transitions через family-row и выполняет consume presented token + insert successor одной transaction. Ordinary revoke теперь terminal для всей family и сериализуется с rotation; он остаётся отдельным от replay compromise. Replay помечает family compromised и отзывает всех active descendants.

`DatabaseRefreshTokenHousekeeper::cleanup($now, $limit)` выполняет bounded housekeeping в два этапа. Сначала он удаляет не более `$limit` history rows, у которых истёк срок именно соответствующего bearer, включая истёкшую history ещё живой sliding family; каждое такое удаление сериализуется через family row. Затем рассматривается не более `$limit` terminal family candidates; family удаляется только после полного drain её history и повторной проверки expiry на primary под той же сериализацией. Поэтому cleanup не может удалить concurrently созданный active successor.

Credential responses получают `Cache-Control: no-store` и `Pragma: no-cache`. Для семантически пустого token response `Content-Type` удаляется явно; семантика response не определяется размером PSR-7 stream, который законно может быть неизвестен.

## Password reset

`PasswordResetServiceInterface` владеет всей recovery transition и password policy. `Success` означает consumed reset token, изменённый пароль и durable/logical invalidation старых session/remember/refresh credentials. `PasswordRejected` является отдельным outcome.

Если password repository и credential stores находятся в разных ресурсах, application implementation должна использовать эквивалент credential version/outbox/idempotent модель и не возвращать success после частичного перехода.

## Events и clocks

Остался один расширяемый listener contract:

```php
interface EventListenerInterface
{
    public array $events { get; }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void;
}
```

Семь event-specific marker interfaces и `ListenerFactory` удалены. `CriticalEventListenerInterface` сохранён из-за самостоятельной fail-fast семантики.

Event DTO не создают `Clock` самостоятельно: timestamp обязателен и передаётся owning service с внедрённым clock. Generic auth/logout events — best-effort observers; critical session events выполняются в owning transition. Best-effort session GC также изолирует scheduler/random/logger failures от уже успешного application response.

Componenta factories также используют общий PSR-20 `ClockInterface` для event timestamps, JWT access/refresh issuance/validation и logout observer time. Constructor defaults остаются только fallback для прямого создания объектов вне стандартного Componenta container.

Credential-bearing DTO скрывают bearer material в debug/JSON. Package-owned exception-prone boundaries редактируют credential-bearing request/context/storage/event/session arguments, generated credential helper values, downstream PSR request-handler objects, application listener/storage objects, DI container objects и SQL database/connection objects, которые могут содержать configuration secrets. PHP parameter attributes не наследуются concrete implementations, поэтому custom strategies, stores, listeners, senders, middleware и factories должны повторять эквивалентные `#[SensitiveParameter]` annotations на собственных credential/config-bearing frames. Third-party implementations отвечают за свои stack frames; application не должна публиковать stack traces внешним клиентам.

## Denials и malformed input

`DeniedReasonInterface::$attributes` — только audit context. Built-in `DeniedResponseFactory` публикует только стабильный `error` code. `PublicDeniedReasonInterface` удалён; richer public body требует custom `DeniedResponseFactoryInterface`.

Strict extractors бросают `InvalidPayloadException`. Production handlers должны находиться за `InvalidPayloadMiddleware` либо эквивалентным mapper в 400.

Cookie-authenticated state-changing endpoints, включая logout там, где это соответствует модели приложения, остаются под application CSRF policy: auth package не может сам определить trusted origin и deployment topology.

## Primary reads и concurrency proof

Credential-state reads session/remember/one-time/refresh/OTP pinned к Cycle WRITE driver: replica lag не может воскресить revoked credential.


Breaking changes описаны в [MIGRATION-v2.md](MIGRATION-v2.md).
