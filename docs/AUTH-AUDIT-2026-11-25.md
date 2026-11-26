# Аудит и исправления Componenta Auth — 25 ноября 2026

Последние результаты: [шестой независимый проход от 26 ноября](AUTH-RECHECK-2026-11-26-PASS6.md).

Результаты второго независимого прохода и дополнительные исправления:
[перепроверка от 26 ноября 2026](AUTH-RECHECK-2026-11-26.md).
Приведённые ниже показатели относятся к первому проходу.

## Результат

Проверены 17 репозиториев семейства: 16 действующих Composer-пакетов и
`auth-session-csrf`, оставленный как указатель миграции в `auth-session-http`.
Прочитаны 223 PHP-файла production-кода. В 12 репозиториях созданы и опубликованы
ветки `fix/auth-audit-2026-11-25`. Изменения разделены по дефектам с
регрессионными тестами; дополнительно закрыты существенные пробелы тестирования
и уточнены контракты интерфейсов.

Базой ядра служит `auth-3` / v3.0.0, а не старый `main` с Auth 2. Для
`auth-app` также выбрана его ветка `auth-3`; для остальных пакетов — текущий
`main` на момент начала проверки. Ниже перечислены проверенные коммиты.

Итоговая совместная проверка: **377 тестов выбрано, 373 выполнены успешно,
4 пропущены, 1 417 assertions, 0 failures и 0 errors**. По сравнению с
исходными наборами добавлено 93 теста. PHPStan и Composer validation проходят
во всех 16 действующих пакетах. Composer audit не сообщил известных advisories
или abandoned dependencies для разрешённого набора зависимостей.

Миграция Identity на Config 4 отложена по прямому указанию пользователя.
Манифесты пакетов и схемы БД в этом наборе исправлений не изменялись.

## Архитектурные решения

1. **Сохранены границы пакетов.** Ядро остаётся независимым от HTTP, DI и БД.
   Транспорт отвечает за публикацию credentials и компенсацию; хранилища — за
   атомарность и жизненный цикл; admission/guards — за решение о допустимости
   субъекта; lifecycle observers — за наблюдение.
2. **Readonly-массив получает собственные проверенные значения.** PHP-ссылки
   внутри входного массива ранее позволяли менять уже проверенную конфигурацию
   или снимок состояния. Исправления копируют элементы по значению, сохраняя
   публичные имена аргументов и свойства. Это защита границы владения данными,
   а не утверждение об удалённой эксплуатации каждого такого случая.
3. **Числовые имена поддерживаются последовательно.** PHP нормализует некоторые
   строковые ключи массива в целые числа. Валидация использует строковое
   представление, хранение сохраняет идентичность ключа, PHPDoc использует
   `array-key`. Это проверено не только в конструкторах, но и при JSON/DB/JWT
   round trip, где применимо.
4. **Публикация credentials имеет полный scope компенсации.** Успешная запись
   storage ещё не означает, что response удалось подготовить и вернуть.
   Установка cache headers также включена в обработку сбоя. Публикуемый batch
   отделён от pending queue, чтобы replacement не отменял собственный credential.
5. **Текущее assurance отделено от исторической свежести.** Историческое
   подтверждение повторного входа может подтверждать свежесть только тех
   методов и capabilities, которые остаются в текущем session evidence.
6. **События отражают окончательное решение guards.** Документирован и проверен
   порядок `EventingAuthenticator(GuardedAuthenticator(Authenticator(...)))`.
   Ошибки наблюдения изолируются, а critical dispatch сохраняет propagation.
   При выдаче credentials admission должен предшествовать необратимым действиям
   стратегии: внешний guard не откатывает уже выполненную выдачу.

## Исправленные дефекты

### Ядро `auth`

- Ошибки provider и lazy iterator в `dispatchObservers()` / `dispatchBestEffort()`
  больше не превращают завершённую аутентификацию в исключение. Критический
  dispatch продолжает распространять ошибку; отказ logger также изолирован.
- `withAttribute()` / `withAttributes()` сохраняют числовые ключи и заменяют
  существующее значение по тому же ключу без перенумерации.
- `Context` отвязывает прямые внешние PHP-ссылки на элементы карты атрибутов.
  Контракт явно ограничен верхним уровнем: объекты и ссылки внутри вложенных
  значений остаются borrowed values, их глубокой заморозки нет.
- `RateLimited::$retryAfter` проверяется при каждом присваивании. Отрицательное
  значение отклоняется с сохранением предыдущего состояния; допустимые записи,
  включая ноль, поддерживаются.
- `PriorityListenerProvider` отклоняет подписки на interface/abstract class,
  которые никогда не могли совпасть с точным runtime class события. Семантика
  точного совпадения и порядок приоритетов сохранены.
- `InvalidCredentials` и `Unauthorized` скрывают audit attributes в JSON/debug
  и защищают аргумент конструктора через `SensitiveParameter`. Прямое чтение
  атрибутов доверенным кодом остаётся доступным.

Дополнительные тесты проверяют запрещённую публикацию credentials при отказе,
`continueOnFailure` при успехе, границы идентификаторов 128/129 байт, остановку
стратегий/guards и обновление порядка слушателей после регистрации.

### HTTP и публикация credentials

- `DeniedResponseFactory` сохраняет собственную проверенную status map.
  Внешняя ссылка больше не может превратить настроенный отказ 403 в ответ 200.
- Числовые denial codes `0` и `42` проходят валидацию и mapping без `TypeError`.
- Queued `ReplacingPayloadStorage` больше не запускает compensation callbacks
  собственного публикуемого credential. Прямая замена ранее pending credential
  по-прежнему отменяет прежнюю очередь.
- Сбой при установке `Cache-Control` / `Pragma` после успешного `store()`
  компенсируется тем же механизмом. Тест подтверждает ровно один запуск callbacks
  в обратном порядке и отсутствие компенсации при успешной публикации.
- На шести HTTP-границах добавлен фактически проверенный `SensitiveParameter`.
  Проверки используют реальные exception frames при включённых аргументах trace,
  а не только Reflection атрибутов интерфейса.
- Debug-представление `CredentialTransportState` скрывает payloads, storage
  internals и секреты в closure captures.

### Сессии и хранилище

- `AssuranceRequirement` сохраняет собственные списки методов/capabilities.
  Изменение переменной вызывающего кода не меняет готовую политику.
- `AuthSession` сохраняет проверенные scalar/null metadata независимо от
  внешних ссылок; после конструктора значение не может стать объектом через alias.
- Свежий historical reauthentication proof не восстанавливает метод/capability,
  удалённый из текущего evidence при privilege-change rotation.
- Числовые metadata names согласованно поддерживаются контрактом и DB hydration.
  Проверен путь create → resume → find → all → rotate, включая различие между
  `0`, `42` и строковым ключом `001`.
- `CredentialKeyring` сохраняет собственные bytes ключей; штатная ротация
  выполняется созданием нового keyring, а не изменением внешней переменной.
- Числовые key IDs работают во всех трёх credential domains и candidate generation.
- `touch()` игнорирует время не позже наблюдаемой последней активности. Небольшая
  обратная корректировка часов больше не нарушает timestamp invariants и не ломает
  последующий resume; обновление при дальнейшем движении времени проверено.
- Перед expiry revocation условие истечения повторяется в `UPDATE`. Устаревший
  resume по-прежнему отклоняется, но не отзывает уже продлённую другим запросом
  сессию. Этот сценарий воспроизведён детерминированным SQLite contract test.
- CSRF middleware и factor-management guard владеют своими массивами trusted
  origins / excluded paths. Изменение caller references не меняет готовую политику.

### Токены, OTP и факторы

- `TokenRequest` сохраняет собственный контекст; числовые ключи контекста
  поддерживаются и при передаче в sender.
- Отмена OTP challenge сохраняет issuance history. Сбой доставки больше не
  обнуляет cooldown и issuance-window budget. Действующая очистка удаляет историю
  после максимального поддерживаемого окна, новая схема БД не требуется.
- `OtpPayload` / `OtpIssue` скрывают plaintext code в JSON/debug;
  `OtpCodeMac` скрывает ключ в debug. Delivery adapter должен явно читать
  `$issue->code`: generic JSON больше не является форматом доставки секрета.
- Исправлен недетерминированный тест неверного OTP: проверяемый неправильный код
  гарантированно отличается от сгенерированного.
- `TotpKeyring` сохраняет проверенные key bytes и поддерживает числовые key IDs;
  сохранены проверки subject binding и штатной ротации.
- Ошибки валидации TOTP enrollment возвращают HTTP 422; неожиданные ошибки
  инфраструктуры продолжают распространяться.
- `WebAuthnConfig` сохраняет проверенный список allowed origins независимо от aliases.

### JWT

- Числовые custom claim names проходят constructor и полный HMAC/RSA round trip.
- Верхний уровень custom-claim map отвязан от прямых внешних references.
  Borrowed nested values явно описаны; вложенные объекты нужно сохранять
  неизменными до signing.
- HMAC/RSA signer debug output больше не проходит по signing configuration
  и не раскрывает ключевой материал. Тесты используют синтетические ключи.

### DI и пакеты без production-изменений

В `auth-session-app` добавлено интеграционное покрытие через реальные ConfigFactory
и DI 5: trusted request source, запрет shadowing по имени/позиции/типу, nullable и
required параметры, отсутствие request, ошибочный тип атрибута, несовместимый тип
параметра, запрет constructor injection и повторное использование контейнера
без сохранения состояния между запросами. Все эти контракты выполнялись;
production-код не менялся. В `auth-app` убран warning от неэффективного импорта в тесте.

В `auth-password`, `auth-magic-link`, `auth-remember-me` и `auth-recovery-code`
дополнительных подтверждённых дефектов не найдено. Их исходники и тесты проверены;
изменений и искусственных веток для них нет. `auth-session-csrf` больше не содержит
отдельного Composer-пакета; актуальная CSRF-реализация проверялась в `auth-session-http`.

## Матрица проверки

Основной запуск: PHP 8.4.28, PHPUnit 12.5.33 / Pest 4.7.8, PHPStan 2.3.7,
PDO SQLite. Каждый пакет проверен с общим Composer workspace, path repositories
на перечисленные source snapshots и platform PHP 8.4.0. Версии path packages
зафиксированы по соответствующим базовым тегам для проверки совместной работы
исправлений; это не утверждение о публикации новых Packagist-релизов.

В таблице число тестов включает четыре явно отмеченных skips.

| Пакет | Исходных тестов | Итоговых тестов | Assertions | Skips | PHPStan / Composer |
| --- | ---: | ---: | ---: | ---: | --- |
| [auth](https://github.com/componenta/auth/tree/fix/auth-audit-2026-11-25) | 36 | 62 | 173 | 0 | PASS |
| [auth-app](https://github.com/componenta/auth-app/tree/fix/auth-audit-2026-11-25) | 11 | 11 | 22 | 0 | PASS |
| [auth-http](https://github.com/componenta/auth-http/tree/fix/auth-audit-2026-11-25) | 5 | 22 | 112 | 0 | PASS |
| [auth-jwt](https://github.com/componenta/auth-jwt/tree/fix/auth-audit-2026-11-25) | 8 | 14 | 35 | 0 | PASS |
| [auth-magic-link](https://github.com/componenta/auth-magic-link/tree/20aaf94c68ba3dbebdae0a3e470e6386f35cbbbf) | 6 | 6 | 33 | 0 | PASS |
| [auth-otp](https://github.com/componenta/auth-otp/tree/fix/auth-audit-2026-11-25) | 24 | 30 | 275 | 0 | PASS |
| [auth-password](https://github.com/componenta/auth-password/tree/55231162f7c7c90269f9d490dcf61a8bc0bbf2b9) | 6 | 6 | 23 | 0 | PASS |
| [auth-recovery-code](https://github.com/componenta/auth-recovery-code/tree/e2adeb5c45565ba1506cbffa692daad55b154da4) | 9 | 9 | 34 | 0 | PASS |
| [auth-remember-me](https://github.com/componenta/auth-remember-me/tree/7b60d8a95a84a661eae72aaf7a2944b2566d2508) | 18 | 18 | 121 | 0 | PASS |
| [auth-session](https://github.com/componenta/auth-session/tree/fix/auth-audit-2026-11-25) | 11 | 16 | 53 | 0 | PASS |
| [auth-session-app](https://github.com/componenta/auth-session-app/tree/fix/auth-audit-2026-11-25) | 1 | 13 | 25 | 0 | PASS |
| [auth-session-database](https://github.com/componenta/auth-session-database/tree/fix/auth-audit-2026-11-25) | 23 | 28 | 115 | 4 | PASS |
| [auth-session-http](https://github.com/componenta/auth-session-http/tree/fix/auth-audit-2026-11-25) | 82 | 85 | 200 | 0 | PASS |
| [auth-token](https://github.com/componenta/auth-token/tree/fix/auth-audit-2026-11-25) | 10 | 14 | 44 | 0 | PASS |
| [auth-totp](https://github.com/componenta/auth-totp/tree/fix/auth-audit-2026-11-25) | 18 | 26 | 71 | 0 | PASS |
| [auth-webauthn](https://github.com/componenta/auth-webauthn/tree/fix/auth-audit-2026-11-25) | 16 | 17 | 81 | 0 | PASS |

Для `auth-session-http` выполнен его полный PHPStan gate **`src tests --level=max`**.
Для остальных пакетов выполнены их объявленные проверки `src --level=max`.
Во всех пакетах `composer validate --strict` и `git diff --check` проходят.

Ядро и `auth-http` дополнительно прошли полные серии на PHP 8.5.13:
соответственно **62 / 173** и **22 / 112**. Эти запуски не добавлены повторно
к общему числу 373 успешно выполненных тестов.

### Mutation gate

Штатная конфигурация `auth-session-http/infection.json5` проверена без изменения
mutators или порогов: Infection 0.35.12, PHP 8.4.28, PCOV 1.0.12, четыре потока.
Initial PHPUnit phase прошёл. Из 256 мутаций тесты уничтожили 231; 25 пережили
проверку. MSI и covered MSI — **90,234375%** при требуемых **80%**; mutation code
coverage — **100%**. Ненулевой остаток мутаций не представлен как полное
доказательство отсутствия дефектов.

## Ограничения и следующие проверки

- Четыре существующих MySQL/PostgreSQL integration tests `auth-session-database`
  пропущены из-за недоступных сервисов. SQLite persistence/lifecycle tests
  выполнены. Результаты реальной конкурентной работы MySQL/PostgreSQL этим
  отчётом не подтверждаются.
- Паттерн получения времени до ожидания блокировки в JWT refresh / token consume
  остаётся отдельной непроверенной гипотезой. Предыдущая динамическая проверка
  JWT была остановлена автоматической проверкой безопасности с общим сообщением
  о возможном cybersecurity risk. Её не возобновляли через другого исполнителя;
  эта гипотеза не включена ни в список подтверждённых дефектов, ни в список
  закрытых исправлений.
- Защита debug/JSON/exception frames относится к явно проверенным границам.
  Она не заменяет правила логирования приложения и безопасные реализации
  внешних storage, logger и delivery adapters.
- Изменения проверены совместным набором исходников. GitHub Actions для этих
  веток отдельно не запускались; опубликованные релизы зависимостей ещё не
  содержат этот набор исправлений.

## Порядок интеграции

1. Интегрировать изменения `auth`, `auth-session` и `auth-token`.
2. Затем `auth-http`, `auth-session-database` и `auth-session-http`.
3. Затем capability packages: JWT, OTP, TOTP, WebAuthn, а также интеграционные
   тесты `auth-session-app` и исправление тестового warning `auth-app`.

Особенно важна связка numeric metadata: изменение `auth-session-database`
предполагает исправленный `auth-session`. При проверке отдельных пакетов до
выпуска патчей нужно подключать согласованные ветки через Composer path/VCS
repositories; после выпуска — обновить разрешённые версии зависимостей.

Переход Identity / связанных app integrations на Config 4 следует выполнять
отдельным изменением. Здесь сохранён действующий стек Config 3 / DI 5.

Обычные команды проверки пакета после разрешения согласованных зависимостей:

```bash
composer validate --strict
composer check
composer audit
```

Для session HTTP дополнительно, в PHP-окружении с включённым PCOV:

```bash
composer mutation
```

## Коммиты исправлений

Ниже приведены опубликованные коммиты, содержание которых совпадает с локально
проверенными деревьями. Git tree hashes сверены после публикации. Этот отчёт
добавляется отдельным документационным коммитом поверх проверенного ядра.

### auth

[Ветка исправлений](https://github.com/componenta/auth/tree/fix/auth-audit-2026-11-25)

- [`cf4971d78d25`](https://github.com/componenta/auth/commit/cf4971d78d252b174365bad0300c73977749d40d) — Fix observer provider failure isolation.
- [`16a2786b6f65`](https://github.com/componenta/auth/commit/16a2786b6f652a2faf13d2704c803ab643325c5e) — Preserve numeric context attribute keys.
- [`d19a024ce42c`](https://github.com/componenta/auth/commit/d19a024ce42cea44e357e006e4e11ce6f32c8cc7) — Snapshot directly referenced context attributes.
- [`35ea1df4f525`](https://github.com/componenta/auth/commit/35ea1df4f525bc5c3ae01214349f8e805a93cfcd) — Validate retry duration on every assignment.
- [`57bad1bdbd11`](https://github.com/componenta/auth/commit/57bad1bdbd11f69bfcae992dd88291fc89718f50) — Reject event subscriptions that cannot be dispatched.
- [`d933f87f0363`](https://github.com/componenta/auth/commit/d933f87f036387fb2104b2a405b3dbcc64da5458) — Cover authentication outcome and policy boundaries.
- [`a78540182c3b`](https://github.com/componenta/auth/commit/a78540182c3bc919f2485eea5d94baac964bb7e7) — Redact built-in denial audit attributes from diagnostics.
- [`eca3aa3786e6`](https://github.com/componenta/auth/commit/eca3aa3786e60008523e3b6d0a2b54af31b20238) — Document and verify guard and observer composition.

### auth-app

[Ветка исправлений](https://github.com/componenta/auth-app/tree/fix/auth-audit-2026-11-25)

- [`df172cdc98cd`](https://github.com/componenta/auth-app/commit/df172cdc98cdffc80949c9a2cdaae586fd227658) — Remove ineffective global import from auth attribute tests.

### auth-http

[Ветка исправлений](https://github.com/componenta/auth-http/tree/fix/auth-audit-2026-11-25)

- [`446e52c29235`](https://github.com/componenta/auth-http/commit/446e52c29235e4fb0d0470b61c08c564505d3d8f) — fix: retain validated denial status mappings by value.
- [`845049297d93`](https://github.com/componenta/auth-http/commit/845049297d932f3802660c13986ffd4754ee4274) — fix: accept decimal denial codes in HTTP status mappings.
- [`b65f961abc6a`](https://github.com/componenta/auth-http/commit/b65f961abc6a3a22026bb59207c292d243531d13) — fix: preserve queued replacement credentials during publication.
- [`fcb0276f1d9c`](https://github.com/componenta/auth-http/commit/fcb0276f1d9c46d4a3b21bb42ca6721ab7323714) — fix: redact credential-bearing HTTP exception arguments.
- [`2111e9151276`](https://github.com/componenta/auth-http/commit/2111e91512761d6dc65e022b42dd918115dc2b89) — fix: redact retained credential transport state from debug output.
- [`83b6231f7c53`](https://github.com/componenta/auth-http/commit/83b6231f7c5325a49685b4770133787eac98790d) — fix: compensate credential publication when cache headers fail.

### auth-jwt

[Ветка исправлений](https://github.com/componenta/auth-jwt/tree/fix/auth-audit-2026-11-25)

- [`a08a9c8060d8`](https://github.com/componenta/auth-jwt/commit/a08a9c8060d8907d7e0e8408e05468e092fefc6e) — Preserve numeric custom JWT claim names.
- [`3cb4256a156c`](https://github.com/componenta/auth-jwt/commit/3cb4256a156c2de6875c4873fee1b4e96f41a6dd) — Snapshot directly referenced custom JWT claims.
- [`1e9e98b15c7f`](https://github.com/componenta/auth-jwt/commit/1e9e98b15c7ffa5753c885c8baea3d982bdf7784) — Redact JWT signing keys from debug output.

### auth-otp

[Ветка исправлений](https://github.com/componenta/auth-otp/tree/fix/auth-audit-2026-11-25)

- [`bed5c7ab844f`](https://github.com/componenta/auth-otp/commit/bed5c7ab844f65e941a1f17e29748e5ae8f82295) — Redact OTP codes and MAC keys from diagnostic output.
- [`31a2ab9408ab`](https://github.com/componenta/auth-otp/commit/31a2ab9408abee98e8a09b09c4b9da2289cd2b1e) — Retain OTP issuance history when revoking challenges.
- [`bdfd6f71c8d2`](https://github.com/componenta/auth-otp/commit/bdfd6f71c8d2e0f998eac96164aa5ab80395d120) — Make OTP failure-budget regression deterministic.

### auth-session

[Ветка исправлений](https://github.com/componenta/auth-session/tree/fix/auth-audit-2026-11-25)

- [`f9475de324cf`](https://github.com/componenta/auth-session/commit/f9475de324cf95ea968d5a501976d02d8dae9598) — fix: snapshot assurance policy identifiers by value.
- [`c22051963667`](https://github.com/componenta/auth-session/commit/c22051963667a9afeeb15a2a870fa6571f3bba69) — fix: retain validated session metadata as an owned snapshot.
- [`970973883a16`](https://github.com/componenta/auth-session/commit/970973883a16d3e88636c83c240d1d00c0ac03ea) — fix: require current evidence before checking assurance freshness.
- [`cdc2106098a4`](https://github.com/componenta/auth-session/commit/cdc2106098a43f6895e209803c613ad4c69eb3b0) — fix: preserve numeric session metadata names.

### auth-session-app

[Ветка исправлений](https://github.com/componenta/auth-session-app/tree/fix/auth-audit-2026-11-25)

- [`5668a08e490d`](https://github.com/componenta/auth-session-app/commit/5668a08e490d9d442f8d22afcb0133d3c7058b7d) — Cover CurrentSession request-bound DI integration.

### auth-session-database

[Ветка исправлений](https://github.com/componenta/auth-session-database/tree/fix/auth-audit-2026-11-25)

- [`8344c862dbae`](https://github.com/componenta/auth-session-database/commit/8344c862dbaef7c8680c3671e7208dcac7ef0dc7) — fix: own validated credential key material.
- [`dac1e2ed1fd0`](https://github.com/componenta/auth-session-database/commit/dac1e2ed1fd0b8237fbe216d98e73152b2ac021b) — fix: accept numeric credential key identifiers consistently.
- [`9e05b83740fd`](https://github.com/componenta/auth-session-database/commit/9e05b83740fdfbffe749564d5663fd1f5c8f6750) — fix: keep authentication session activity monotonic.
- [`66a824498afb`](https://github.com/componenta/auth-session-database/commit/66a824498afbe2a8815887ac6c8f66b436b689c4) — fix: recheck expiry before revoking a resumed session.
- [`01cbcb995f99`](https://github.com/componenta/auth-session-database/commit/01cbcb995f993780f4cb0bd79f98138e78463a2b) — fix: hydrate numeric session metadata keys without losing identity.

### auth-session-http

[Ветка исправлений](https://github.com/componenta/auth-session-http/tree/fix/auth-audit-2026-11-25)

- [`e00f29290e35`](https://github.com/componenta/auth-session-http/commit/e00f29290e35a5fff53e5a7354f2677b931f36ab) — fix: snapshot browser security configuration arrays.

### auth-token

[Ветка исправлений](https://github.com/componenta/auth-token/tree/fix/auth-audit-2026-11-25)

- [`145585dd4598`](https://github.com/componenta/auth-token/commit/145585dd459888765092feb7ac642f0e7e6d08bc) — Preserve validated token request context snapshots.
- [`f30fed77ade0`](https://github.com/componenta/auth-token/commit/f30fed77ade007aac6f754dadf2553f97019c8d2) — Accept numeric token request context keys.

### auth-totp

[Ветка исправлений](https://github.com/componenta/auth-totp/tree/fix/auth-audit-2026-11-25)

- [`a9abcfffcb08`](https://github.com/componenta/auth-totp/commit/a9abcfffcb08c0f5f5869cef5efe9e2294ba9330) — fix: accept decimal TOTP key identifiers.
- [`35c9ec07bca8`](https://github.com/componenta/auth-totp/commit/35c9ec07bca8b358a549ac5a65992e9b19dae543) — fix: retain TOTP key material independently of input references.
- [`465899ae466e`](https://github.com/componenta/auth-totp/commit/465899ae466ebf2bc262003b148035e1ddeec5b6) — fix: map invalid TOTP enrollment input to HTTP 422.

### auth-webauthn

[Ветка исправлений](https://github.com/componenta/auth-webauthn/tree/fix/auth-audit-2026-11-25)

- [`a6f220acfc8a`](https://github.com/componenta/auth-webauthn/commit/a6f220acfc8a4833e91279c811af118d6b59bd1b) — fix: retain validated WebAuthn origins independently of input references.
