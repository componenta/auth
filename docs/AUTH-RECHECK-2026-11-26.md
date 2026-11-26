# Независимая перепроверка Componenta Auth — 26 ноября 2026

Последние результаты:
[четвёртый независимый проход](AUTH-RECHECK-2026-11-26-PASS4.md).
Четыре дополнительных исправления предыдущего этапа:
[третий независимый проход](AUTH-RECHECK-2026-11-26-PASS3.md).
Приведённые ниже показатели относятся ко второму проходу.

## Результат и область

Это второй проход после [первого аудита](AUTH-AUDIT-2026-11-25.md).
Заново проверены исправления, их реальные потребители и совместная работа
16 активных Composer-пакетов. `auth-session-csrf` повторно проверен как
архивный указатель миграции; исполняемого пакета в нём нет. После исправлений
активные пакеты содержат 231 PHP-файл в `src`.

Дополнительные изменения опубликованы в 11 репозиториях: 24 коммита с
исправлениями, тестами и уточнением документации. Этот отчёт добавлен отдельным
коммитом. Сохранено имя ветки `fix/auth-audit-2026-11-25`. Для `auth-password`,
`auth-magic-link` и `auth-recovery-code` эта ветка создана в данном проходе;
для остальных использованы уже опубликованные audit-ветки. В сумме audit-ветки
существуют в 15 активных пакетах. `auth-remember-me` остался без изменений.

**Итог: 478 выбранных тестов, 474 успешно выполнены, 4 native DB skips,
1 971 assertions, 0 failures, 0 errors.** Ещё два существующих OTP-теста
ожидания блокировки намеренно не запускались и не входят в число 478.
По сравнению с первым проходом в suites добавлено 103 тестовых случая.

Применены `design-software-interfaces`, `php-best-practices`, `php-testing`
и TDD: сначала публичное воспроизведение нарушения контракта, затем исправление
и отрицательные контроли. Работа разделялась по пакетам; дополнительно проведён
взаимный review изменений ядра, JWT и транспортной машины состояний.
Существующий отчёт и зелёные исходные suites не использовались как доказательство
отсутствия ошибок.

## Подтверждённые проблемы и исправления

### 1. Отложенная credential перезаписывала результат нового входа

В OTP, magic link и WebAuthn login handlers отсутствовала граница отмены
предыдущей выдачи, уже существовавшая в `PasswordLoginHandler`. Обработчик
публиковал новую session cookie, после чего внешний middleware вызывал
`CredentialTransportState::apply()` и записывал старую отложенную credential
поверх новой.

Воспроизведение использовало штатный `SessionCookieTransport`, а не специально
сломанный storage. Для WebAuthn использована настоящая P-256 подпись тестового
аутентификатора. Дополнительный случай показал публикацию отложенной cookie
даже после отказа финального admission при попытке нового WebAuthn-входа.

Теперь все четыре login callers `sessionIssuer->issue()` отменяют pending
transport **до** создания новой сессии. Отмена отнесена к владельцу нового
входа. Общий publisher и reauthentication handlers не получили безусловный
`discardQueued()`: для ротации существующего UUID такое вмешательство могло
отозвать уже созданное поколение через чужой compensation callback.

RED/GREEN: OTP и magic link — по одному падающему случаю с pending credential
при проходящем контроле без неё; WebAuthn — два падающих случая в наборе из шести.
После исправления новая cookie сохраняется, а cancellation callback выполняется
один раз.

### 2. Ошибка публикации оставляла созданный pre-auth grant активным

Неполная область компенсации обнаружена в `PreAuthenticationStartHandler`,
`OtpLoginRequestHandler`, `MagicLinkRequestHandler` и
`WebAuthnLoginOptionsHandler`. В зависимости от обработчика исключения response
factory, записи тела, установки cookie, request-token или cache headers
возникали уже после создания grant, но вне существующего `try/catch`.

Теперь каждый из четырёх callers компенсирует ошибку после создания grant
через `consume()` с его точными credential и request token. Успешная выдача
оставляет grant пригодным для использования. В OTP/magic link ошибка подготовки
публикации не запускает delivery queue. WebAuthn сохраняет существующий жизненный
цикл ceremony; недоступным становится её browser pre-auth binding.

Первоначальные RED: session HTTP — четыре стадии отказа; OTP и magic link —
по три стадии publisher; WebAuthn — пять стадий body/headers/publication.
Это подтверждённый дефект управления неопубликованным состоянием. Наличие
неотозванного grant само по себе не доказывает, что посторонний знает его
случайные секреты или способен завершить вход.

### 3. Terminal clear не отменял уже выполняющуюся публикацию

Предыдущее исправление `CredentialTransportState` правильно отделило активный
batch от pending work, чтобы `ReplacingPayloadStorage` не отзывал собственную
выдачу. Повторный review обнаружил другую границу: вызванный из storage или
response callback `clear()` выставлял terminal flag, но активный batch мог
продолжить работу и потерять свои callbacks как успешно опубликованный.

Теперь публикация перечитывает terminal state после внешних операций,
останавливает оставшиеся `store()`, компенсирует активный batch и удаляет
зарегистрированные credentials. Дополнительно исправлена регистрация другого
transport во время `remove()` или удаления заголовков: registry обрабатывается
до исчерпания новых transport instances, каждый instance — один раз за `apply()`.

Две исходные регрессии на active batch и две на новый transport были RED.
Проверены LIFO, исполнение callbacks до возврата/ошибки, повторный clear из
compensation/removal, ошибки cleanup/removal и изоляция request-scoped state.
Семантика `ReplacingPayloadStorage` сохранена.

Это ошибки публичного lifecycle/extension-контракта с локальными допустимыми
collaborators. Удалённый путь атаки через штатные cookie transports для этих
двух случаев не заявляется. Произвольный рекурсивный `apply()` и бесконечное
создание новых transports пользовательским callback не объявлены поддерживаемым
протоколом.

### 4. Частичная запись stream считалась готовым JSON-ответом

`StreamInterface::write()` возвращает фактическое число записанных байтов.
Одна запись не устанавливает постусловие «весь JSON находится в response».
Это проверено по [контракту PSR-7](https://www.php-fig.org/psr/psr-7/#34-psrhttpmessagestreaminterface)
и установленной реализации Nyholm, вызывающей `fwrite()`.

Найдено и исправлено 13 мест в восьми пакетах: два auth HTTP error responses,
две JWT token publications, OTP request, magic-link request, два password-reset
responses, recovery regeneration, TOTP enrollment и три WebAuthn options
responses. Публичные тесты показали неполный JSON при успешном HTTP status,
а в JWT — также оставшийся активным неопубликованный refresh credential.

Package-local `@internal JsonResponseBody` / `TokenResponseBody` дописывают
остаток по фактической длине. Каждая успешная итерация уменьшает остаток;
нулевой, отрицательный или невозможный byte count вызывает исключение.
Исключения самого stream сохраняются. В JWT helper находится внутри существующей
области отзыва нового refresh token. В OTP, magic link и password reset тело
готовится до grant/queue/reset transition.

Использованы complete, partial, partial-then-stall и partial-then-exception
контроли. Для auth HTTP отдельно проверены нулевая запись сразу и после части
тела. Нет новых связей между версиями пакетов: helpers используются только
внутри своих пакетов, не требуют новой публичной API в другом репозитории.

### 5. Ранняя ошибка ответа уничтожала прежние recovery codes

`RecoveryCodeRegenerateHandler` вызывал `regenerate()` до создания response
и подготовки headers. Отказ response factory или header operation уже оставлял
пользователя без прежнего batch, хотя новые коды ещё не могли быть возвращены.

Теперь response и headers готовятся до замены batch. Два публичных RED/GREEN
сценария используют реальный SQLite manager и разрешённый запрос через factor
guard: после раннего отказа прежний recovery code всё ещё можно consume.

Граница гарантии существенна: сбой stream **после** regeneration не восстанавливает
прежние коды. Полная запись устраняет ложный успешный ответ при частичном I/O,
но не делает commit БД и доставку HTTP атомарными. Добавлять `revokeAll()` в этот
catch означало бы дополнительно уничтожить новый batch; такой компенсации нет.

### 6. Неправильный TOTP label заменял ожидающее подключение

`DatabaseTotpManager::beginEnrollment()` сохранял новый pending secret до
`getProvisioningUri()`. OTPHP проверяет часть сочетаний label/issuer при построении
URI, поэтому `Other:User` и `Other%3AUser` приводили к `422`, но уже заменяли
прежнее ожидающее подключение.

URI теперь формируется и проверяется до записи. Два HTTP + SQLite regression
теста сначала падали; теперь прежний enrollment code продолжает подтверждаться
после `422`. Активный TOTP factor этим путём не отключался, management guard
не обходился.

### 7. Ротация сессии могла сдвинуть activity назад

Предыдущая защита `touch()` не распространялась на `rotate()`. При расхождении
часов ротация могла записать `last_active_at` раньше сохранённого значения,
а при времени раньше первоначального входа — нарушить инварианты `AuthSession`.

Логическое время ротации теперь равно более позднему из wall clock и
`last_active_at` загруженной строки. Девять сценариев покрывают три причины
rotation, равное время, отставание на секунду и время раньше рождения сессии.
Проверены устаревший caller snapshot, lifecycle поколений, последующая обычная
ротация и absolute-expiry cap для non-reauthentication.

Вариант с новым исключением при обратном времени был отклонён при review:
вызывающие handlers уже расходуют одноразовый proof, а новый throw добавлял бы
`500`. Clamp сохраняет возможность ротации; freshness не принимает future-dated
reauthentication proof до выравнивания wall clock. Это гарантия относительно
загруженной строки, а не новая гарантия serializable ordering при concurrent
`touch()` после SELECT.

### 8. Допустимое имя класса подписки принималось, но listener не вызывался

`PriorityListenerProvider` валидировал PHP class name, затем сравнивал исходную
строку с runtime class без нормализации. Имя с ведущим `\`, другой регистр и
class alias проходили регистрацию, но не совпадали при dispatch.

Теперь эквивалентные имена разрешаются к одному concrete class. Подписки по
наследованию не включены: отдельный negative control подтверждает отсутствие
вызова parent listener для child event. Три случая были RED, после исправления
проходят; сохраняются приоритеты и регистрационный порядок. Семантика aliases
сверена с [PHP manual](https://www.php.net/manual/en/function.class-alias.php).

### 9. Проверки, дополненные без нового production fix

В WebAuthn первый повторный запуск обнаружил настоящий flaky test: OpenSSL
иногда возвращает 31-байтовую координату P-256, а fixture объявлял 32 байта в CBOR.
Использован явно синтетический постоянный тестовый ключ с этой границей;
координаты дополняются до 32 байт. Все admission scenarios продолжают проходить
реальную криптографическую валидацию.

В OTP добавлен end-to-end regression на delivery failure: код отозван,
issuance history/budget сохранены, исходное исключение не потеряно. Положительный
контроль проверяет однократную применимость успешно доставленного кода.

Повторно подтверждены прежние snapshot/numeric-key fixes, current evidence
против исторического proof, CSRF configuration ownership, admission boundaries,
primary-read consistency, remember-me restore/logout и DI request isolation.
Дополнительно выполнены 56 обычных проверок жизненного цикла для numeric key IDs
`0`, `42`, `001`, `9223372036854775808` в session, pre-auth и TOTP. Они не включены
повторно в итоговую PHPUnit-матрицу.

## Матрица финального прогона

PHP 8.4.28; PHPUnit 12.5.33 / Pest 4.7.8; PHPStan 2.3.7; PDO SQLite.
Использован общий Composer workspace с path repositories на согласованные
исходники и platform PHP 8.4.0. Версии path packages соответствуют базовым тегам;
это не утверждение, что исправления уже входят в опубликованные релизы.

| Пакет | Выбрано | Успешно | Skipped | Assertions |
| --- | ---: | ---: | ---: | ---: |
| auth | 66 | 66 | 0 | 178 |
| auth-app | 11 | 11 | 0 | 22 |
| auth-http | 38 | 38 | 0 | 167 |
| auth-jwt | 22 | 22 | 0 | 71 |
| auth-magic-link | 15 | 15 | 0 | 80 |
| auth-otp | 41 | 41 | 0 | 334 |
| auth-password | 14 | 14 | 0 | 65 |
| auth-recovery-code | 15 | 15 | 0 | 59 |
| auth-remember-me | 18 | 18 | 0 | 121 |
| auth-session | 16 | 16 | 0 | 53 |
| auth-session-app | 13 | 13 | 0 | 25 |
| auth-session-database | 37 | 33 | 4 | 229 |
| auth-session-http | 89 | 89 | 0 | 209 |
| auth-token | 14 | 14 | 0 | 44 |
| auth-totp | 32 | 32 | 0 | 90 |
| auth-webauthn | 37 | 37 | 0 | 224 |
| **Всего** | **478** | **474** | **4** | **1971** |

PHPStan `src --level=max` проходит для всех пакетов; для `auth-session-http`
проверены `src tests --level=max`. Во всех 16 пакетах прошли
`composer validate --strict` и `git diff --check`. Повторный Composer audit
вернул пустые `advisories` и `abandoned` для разрешённого набора зависимостей.

После последних двух WebAuthn-изменений повторены только его полный PHPUnit,
PHPStan, Composer validation и diff check; строка матрицы обновлена по этому
прогону. Остальные исходники оставались неизменными. Последующие изменения
README/этого отчёта не меняли исполняемый код.

Дополнительный PHP 8.5.13: final auth HTTP — 38 / 167, session HTTP — 89 / 209,
оба без skips; ядро — targeted provider regression 7 / 9. Remember-me на этом
runtime выполнил 10 тестов и пропустил 8 SQLite cases; все 18 реально выполнены
на PHP 8.4.28. Дополнительные запуски не сложены с основной матрицей.

### Mutation gates

- Штатный `auth-session-http/infection.json5`, без изменения mutators или порогов
  80/80: 259 mutants, 234 killed, 25 escaped; **MSI 90,35%, PASS**.
- Дополнительный focused run auth HTTP для `CredentialTransportState` и
  `JsonResponseBody`: 64 mutants, 48 killed, 9 escaped, **7 timed out**;
  стандартный Infection MSI **85,94%, PASS**. Он включает timeouts;
  эти семь не представлены как test kills.
- Первый focused run выявил слабое наблюдение в тесте: компенсация проверялась
  после дополнительного ручного discard. Проверка перенесена до него;
  соответствующий mutant теперь уничтожается. Пороги не снижались.
- `Mutation Code Coverage` относится к сгенерированным mutants. Default run
  без `--with-uncovered` не устанавливает 100% line coverage всего пакета.

## Публикация и проверенные коммиты

Каждый опубликованный tree SHA сверен с локальным деревом проверенного коммита.
После публикации ветки fetched, локальные ссылки приведены к тем же remote HEAD;
код не объединялся с main и релизы не создавались. Таблица содержит последние
коммиты набора до добавления этого отчёта.

| Пакет | Коммит | Дополнительных коммитов |
| --- | --- | ---: |
| auth | [4cd6140](https://github.com/componenta/auth/commit/4cd6140dd85ddd5b1e7bb2a51a5d0168de00a407) | 1 |
| auth-http | [b7582c9](https://github.com/componenta/auth-http/commit/b7582c9752fa01a891f44ff12925092500eed805) | 4 |
| auth-jwt | [250895c](https://github.com/componenta/auth-jwt/commit/250895cceff39f1e6d465da0ea77912b075e8abb) | 1 |
| auth-magic-link | [30abe16](https://github.com/componenta/auth-magic-link/commit/30abe166ccd524fa5261a2f452323ccae4e99415) | 3 |
| auth-otp | [630b260](https://github.com/componenta/auth-otp/commit/630b2609c6c542bbf827f1ca03503b8376304d40) | 4 |
| auth-password | [8e04a0e](https://github.com/componenta/auth-password/commit/8e04a0ec6cd01ad54588fe6ca9c90d618b3b7e7e) | 1 |
| auth-recovery-code | [448f791](https://github.com/componenta/auth-recovery-code/commit/448f7913c2afdb88e8c5b769ab9ec971156b28e7) | 2 |
| auth-session-database | [2c3197f](https://github.com/componenta/auth-session-database/commit/2c3197f245164d5c3b13b6c441e0d004efb7f45b) | 1 |
| auth-session-http | [b86426b](https://github.com/componenta/auth-session-http/commit/b86426b2bbbf710a9b1622c86e5cdc601ff8aa3f) | 1 |
| auth-totp | [eb2cce8](https://github.com/componenta/auth-totp/commit/eb2cce835932ba4d1c2de79e21f9d6cc690352c2) | 2 |
| auth-webauthn | [0f27eb3](https://github.com/componenta/auth-webauthn/commit/0f27eb360aa8d355d0957d4f04392f229a81d47c) | 4 |

У `auth-app`, `auth-session`, `auth-session-app`, `auth-token` новых изменений
второго прохода нет; использованы ранее опубликованные audit HEAD.
У `auth-remember-me` новых подтверждённых дефектов в этой области не найдено,
его main оставлен без изменений.

## Что не считается проверенным или атомарным

1. **Native MySQL/PostgreSQL.** Четыре existing vendor integration cases остаются
   skipped. Для PostgreSQL 17.12 создан свежий изолированный test cluster,
   но запуск остановился на создании Unix socket с `Operation not permitted`.
   Сервер не стартовал, временный cluster удалён. Результаты настоящей
   конкурентной работы этих СУБД не подтверждены SQLite-тестами.
2. **Timing/lock-boundary гипотеза.** Предыдущую динамическую проверку JWT
   lock-wait остановила автоматическая проверка безопасности с общим сообщением
   о возможном cybersecurity risk. Она не возобновлялась через другой агент
   или инструмент. Раннее чтение clock в JWT refresh / token consume остаётся
   неподтверждённым статическим наблюдением. Два existing OTP
   `LockWaitExpiryTest` cases также исключены из этого повторного запуска.
3. **Commit и HTTP delivery.** После regeneration recovery codes исключение
   stream не возвращает прежний batch. Pending TOTP enrollment и WebAuthn
   ceremony сохраняют существующие TTL/lifecycle после соответствующих ошибок.
   Pre-auth grant и JWT refresh компенсируются там, где их caller владеет
   подходящей операцией отзыва. Это не распределённая транзакция с браузером.
4. **Граница collaborators.** Транспортная state machine обрабатывает конечные
   callbacks описанного контракта. Она не изолирует произвольный недоверенный
   PHP-код, бесконечные callbacks или недоступную БД. Error precedence уточнён:
   первая ошибка внутри каждого compensation pass; более поздний pass может
   заменить ошибку вложенного clear.
5. **CI и production.** GitHub Actions отдельно не запускались. Локальные suites,
   static analysis, mutation gates и content equality опубликованных деревьев
   проверены; эксплуатация, нагрузочное тестирование и production concurrency
   не заявляются как выполненные.

## Совместимость и интеграция

Манифесты всех 16 пакетов, существующие PHPUnit/Infection configurations,
публичные конструкторы и схемы БД не изменены. Новые JSON helpers внутренние
для своих пакетов. Сохранены текущие границы admission, trusted request,
одноразовых credentials и наблюдательных событий.

Identity и переход на Config 4 остаются отдельной задачей по указанию пользователя.
Действующий стек Config 3 / DI 5 сохранён. Для интеграции следует использовать
согласованный набор audit-веток, затем выпустить соответствующие версии;
совместимость первого прохода, включая numeric metadata между session и
session-database, всё ещё требует этих согласованных исходников.

Для локального повторения после подключения согласованных зависимостей:

```bash
composer validate --strict
vendor/bin/phpstan analyse src --level=max
```

Обычные PHPUnit-пакеты запускаются через `vendor/bin/phpunit`; auth-app — через
`vendor/bin/pest`. В данном повторном прогоне для OTP использован точный фильтр:

```bash
vendor/bin/phpunit --filter '/^(?!.*LockWaitExpiryTest).*$/'
```

Для session HTTP static analysis включает `src tests`, а штатный mutation gate:

```bash
vendor/bin/infection --threads=4 --min-msi=80 --min-covered-msi=80 --no-progress
```

Вывод этого прохода ограничен приведёнными контрактами и доказательствами.
Наличие проходящих suites и mutation score не трактуется как доказательство
отсутствия всех возможных уязвимостей.
