# Auth 3 — повторный аудит и публикация исправлений

Дата: 27 сентября 2026 года. Область: все 16 пакетов Auth 3, указанных в матрице ниже. Это проверка библиотек и их совместной сборки, а не сертификация приложения по OWASP ASVS и не аудит работающего ecom.

## Итог и статус публикации

Недостающие исправления опубликованы непосредственно в существующих ветках. В рамках этого прохода создано **10 функциональных коммитов в 7 репозиториях**, добавлено **26 тестовых случаев**. Новые ветки, pull requests, force push и Co-authored-by не использовались.

Финальная проверка именно опубликованного набора: **213 пакетных тестов / 781 assertion**, дополнительно **6 межпакетных конкурентных тестов / 36 assertions**. Всего **219 тестов / 817 assertions**, без ошибок, падений и пропусков. PHPStan max прошёл для всех 16 пакетов. Composer audit завершился с кодом 0; advisories и abandoned пусты.

Архитектуру Auth 3 сохраняем. Ацикличные межпакетные зависимости, transport-neutral ядро, отдельные identity/evidence/session credential и явный финальный допуск не требуют переписывания. Исправления сосредоточены на отказных сценариях, согласованности хранилищ, свежести доказательств и безопасной диагностике.

## 1. Что уже было опубликовано до переноса архива

Архив предыдущего этапа не применялся поверх изменившихся веток вслепую. На актуальных HEAD уже присутствовали `AuthenticationAdmission` с повторным разрешением canonical identity, обязательный допуск в `AuthenticatedSessionIssuer`, обработка его отказов в нескольких способах входа, `FactorManagementGuard`, защита TOTP/recovery handlers, primary reads remember-me и сериализация recovery-code batches.

Эти независимые изменения сохранены. В частности, issuer продолжает принимать **AuthenticationAdmission**, а не более слабую замену из старого архива с одним прямым вызовом guard. Для управления факторами использован уже опубликованный guard с ограниченным `AssuranceRequirement`; отдельный `FactorManagementPolicyInterface` из локального прототипа не добавлен. Различающиеся политики endpoint можно задавать разными экземплярами guard. Это перенос защитного поведения на текущие контракты, а не побайтовое повторение устаревших патчей.

В свежем исходном снимке было 187 пакетных тестовых случаев. Тесты проходили, но PHPStan обнаруживал неучтённый union-результат issuer в WebAuthn. После добавления недостающих проверок и новых регрессий итог — 213 случаев.

## 2. Опубликованные коммиты этого прохода

| Пакет | Commit | Изменение |
|---|---|---|
| auth-jwt | `c3bdd88b8108ba48e7a8a8ecfaa1c23d83702e48` | Обязательный guard; компенсация всех отказов после refresh rotation |
| auth-remember-me | `5b84d7de0669e68d912d411a49fe545741d457aa` | Очистка очереди credentials даже при исключении отзыва |
| auth-webauthn | `bec12c428f6757f674ea194481344c57d1f213ae` | Обязательный guard и обработка terminal denial issuer |
| auth-webauthn | `1d06c952056f42c5cf994d674560b08f9c4b3d17` | Защита обоих этапов регистрации ключа |
| auth-otp | `8fa850708d041185ec4f71584f45486e568dbbfb` | Проверка времени после ожидания budget lock |
| auth-token | `335b159a522283767068690d0f711ae1144b4e2a` | Авторитетное чтение одноразовых токенов |
| auth-webauthn | `67aadc6e7eea7155e740be431f62a32282e8f69d` | Авторитетное чтение ceremonies и credentials |
| auth-session-database | `e1a854e7e686279eb1b29680afc295e3c142237e` | Авторитетное чтение pre-authentication |
| auth-session-database | `21b6ab1b1832f0663a5fa661d4a5787010786e03` | Редактирование ключей в диагностике |
| auth-totp | `4408b6fdc04990a228b0d3731246d2120f9e0036` | Редактирование ключей шифрования в диагностике |

Все обновления refs выполнены без force. Итоговый CI manifest содержит перечисленные конечные коммиты; скачанные опубликованные исходники сопоставлены с локально проверенными файлами и повторно протестированы.

## 3. Подтверждённые дефекты и их проверка

### R-01. JWT: исключение финального guard оставляло активный непубликованный successor

`RefreshHandler` выполнял часть fallible operations после ротации вне блока компенсации. Исключение повторной проверки аккаунта оставляло новый refresh token активным, хотя успешного ответа клиенту не было.

Теперь повторное разрешение identity, проверка subject/evidence, guard и построение ответа охвачены компенсацией. На исключении successor отзывается. Guard является обязательной одиночной зависимостью. При отказе самого хранилища отзыва ошибка инфраструктуры не выдаётся за успешно выполненный отзыв.

Доказательство: `RefreshHandlerFailureTest::testExceptionFromFinalGuardRevokesTheUnpublishedSuccessor`, реальное SQLite-хранилище, проверка нуля активных непубликованных токенов. До исправления тест падал. `AdmissionConfigurationTest` закрепляет обязательность зависимости. Логи: `jwt-red`, `jwt-green`. Риск зависит от исключений после ротации; произвольный обход подписи JWT не установлен.

### R-02. Remember-me: исключение отзыва оставляло очередь публикации

В `RememberMeSessionMiddleware` вызов `revokeRotation()` предшествовал `discardQueued()`. При его исключении очередь оставалась заполненной. Теперь очистка выполняется в `finally` при отказе и исключении финального допуска.

`SessionAdmissionCompensationTest` проверяет обычный отказ, исключение admission и исключение revocation. Последний случай воспроизводил дефект до исправления. Проверяются отсутствие создания сессии, очистка очереди, снятие authentication attributes на обычном отказе и отсутствие Set-Cookie при последующей обработке очереди. Логи: `remember-red`, `remember-green`.

Это исправление состояния публикации. Оно не может гарантировать durable revocation при недоступной БД; исключение сохраняется как ошибка, а не успешный logout.

### R-03. WebAuthn: несовместимость issuer и незакрытые HTTP-границы

Login и reauthentication передавали отказ issuer в publisher, ожидающий grant, вызывая TypeError. Optional variadic guards позволяли не задать проверку допуска. Обработчики регистрации ключа не использовали уже имеющийся общий guard.

Добавлены обязательный guard для login, явная обработка `DeniedReasonInterface` для login/reauthentication и обязательный `FactorManagementGuard` в options/complete handlers. Проверки выполняются до операций регистрации. Gate контролирует POST, владельца, актуальность и поколение сессии, ограниченную свежесть допустимого доказательства, canonical admission и session-bound CSRF.

`LoginAdmissionTest` использует настоящий P-256 ключ и подпись виртуального аутентификатора, реальную библиотеку WebAuthn и SQLite. Проверены разрешённый вход, ранняя блокировка и отказ непосредственно при выдаче сессии. Подлинное криптографическое доказательство не отменяет account admission. `RegistrationAuthorizationTest` проверяет GET и identity без сессии для обоих этапов. Логи: `webauthn-red`, `webauthn-green`. Общие проверки CSRF/assurance находятся также в тестах `auth-session-http`.

### R-04. OTP принимался после истечения срока во время ожидания блокировки

Новая находка повторного аудита: `DatabaseOtpChallengeStore::verify()` вычислял `$now` до `acquireBudgetLock()`. Задержавшийся запрос проверял истечение относительно устаревшего времени. Правильный код принимался как Verified; неправильный код расходовал попытку уже просроченного challenge.

Время теперь читается после получения блокировки. `LockWaitExpiryTest` с двумя наборами данных переводит FrozenClock на 301 секунду вперёд точно на SQL-границе захвата lock. Оба исходных сценария падали; после исправления возвращают Invalid без потребления challenge и изменения attempts. Логи: `otp-lock-red`, `otp-lock-green`.

Это детерминированная регрессия с реальным SQL и моделированием прошедшего времени, а не нагрузочное испытание всех возможных ожиданий БД. Она не заменяет анализ длительных внешних транзакций приложения.

### R-05. Остаточные security reads выполнялись с отстающей реплики

В `DatabaseTokenManager`, `DatabasePreAuthenticationManager` и `DatabaseWebAuthnStore` обнаружены обычные SELECT, которые могли использовать read-driver. Воспроизведены недоступность свежего токена/challenge до репликации и отображение использованного proof или удалённого WebAuthn credential как действующего.

Чтения переведены на writer с сохранением префикса таблиц. Добавлены 3 теста `auth-token`, 2 pre-authentication и 2 WebAuthn. Используются независимые SQLite primary/replica соединения с намеренно устаревшей копией. Логи: `token-primary-red/green`, `preauth-red/green`, `webauthn-primary-red/green`.

Важно: исходные атомарные consume/CAS уже ограничивали повторное использование. Этими тестами установлены нарушения актуальности чтения и доступности, а не произвольный повторный вход с использованным токеном. Writer также не отменяет snapshot-семантику выбранного уровня изоляции.

### R-06. Keyring раскрывал ключевой материал через диагностический дамп

`CredentialKeyring` и `TotpKeyring` не переопределяли `__debugInfo()` и не отмечали массив ключей конструктора `SensitiveParameter`. `var_dump()` содержал синтетический секрет в открытом виде.

Добавлены редактированный debug output и атрибут чувствительного аргумента. По два теста на пакет проверяют отсутствие ключа в дампе, наличие REDACTED и атрибут параметра. Логи: `keyring-red`, `keyring-green`. Криптографические алгоритмы и persisted ciphertext не изменены.

Защита касается этих штатных диагностических каналов. Она не защищает от произвольной reflection-сериализации, дампа памяти, raw serialize или неверно настроенного стороннего logger. Утечка реальных production-ключей в ходе аудита не установлена.

## 4. Ранее открытые конкурентные сценарии

В финальном CI выполнены существующие межпакетные тесты с независимыми процессами и реальными конкурирующими транзакциями:

- MySQL 8.4 и PostgreSQL 17: параллельная генерация первого recovery-code batch и замена существующего — остаётся один batch.
- MySQL REPEATABLE READ и PostgreSQL READ COMMITTED: OTP-запрос, ожидающий завершения соседней транзакции, видит исчерпанный агрегатный бюджет и не потребляет свой challenge.

Итого 6 тестов / 36 assertions, пропусков нет. Recovery storage fix уже присутствовал в опубликованном коде до его финальной проверки здесь; он не включён в список десяти новых коммитов. Старые гипотезы не выдаются за новые неисправленные баги, но эти шесть сценариев не являются доказательством всех interleavings.

## 5. Матрица проверенного набора

Для всех строк: пакетные тесты и PHPStan max успешны. В `auth` и `auth-app` проверена ветка `auth-3`, в остальных — `main`. Commit ядра ниже относится к исполняемому снимку до добавления этого отчёта.

| Пакет | Проверенный commit | Тесты / assertions | Основной предмет повторной проверки |
|---|---|---:|---|
| auth | `c7dd10a3e1eb42b5b402c9e15b8faf46ee5c0ea6` | 32 / 98 | Стратегии, terminal/soft denial, evidence, canonical admission, events |
| auth-app | `5feba20ac4367101e5d147a1096a44b780facb5f` | 11 / 22 | Invocation-only identity, отсутствие request-state singleton |
| auth-http | `c6835c11bfed419ea523deb889d8dbc4810fe6b6` | 5 / 45 | Извлечение credentials, цепочка middleware, очередь публикации и компенсация |
| auth-jwt | `c3bdd88b8108ba48e7a8a8ecfaa1c23d83702e48` | 8 / 22 | Ограничения проверки JWT, refresh family, финальный guard и исключения |
| auth-magic-link | `b8b61424bd87488724af42a8f850c9fe21994c73` | 6 / 33 | Purpose/binding, pre-auth, consume и issuer denial |
| auth-otp | `8fa850708d041185ec4f71584f45486e568dbbfb` | 15 / 44 | Бюджеты, retention, одноразовость, expiry после lock |
| auth-password | `1fa1bf82665252dad610535177ccb1227cd02b5b` | 6 / 23 | Dummy verification, границы ввода, pre-auth, reset-контракт |
| auth-recovery-code | `66dc2424ec3c622f0a79682254a8b56867d6f528` | 8 / 31 | Subject lock, batch replacement, consume и HTTP gate |
| auth-remember-me | `5b84d7de0669e68d912d411a49fe545741d457aa` | 15 / 97 | Family rotation, primary state, session binding и отказ публикации |
| auth-session | `879910c48fcc40570a5518dda597f723eefdc381` | 11 / 40 | Identity ownership, assurance freshness, issuer admission |
| auth-session-app | `fe85df9b4533009d07c2f4ac5b15e3b70dcf987e` | 1 / 6 | Request-local разрешение сессии |
| auth-session-database | `21b6ab1b1832f0663a5fa661d4a5787010786e03` | 23 / 81 | Rotation/touch CAS, отзыв, UTC cleanup, pre-auth, key redaction |
| auth-session-http | `6004585ebb7b52783088ea1612f7f7b1c8c518d9` | 30 / 77 | Cookie/pre-auth, session-bound CSRF, factor management, публикация |
| auth-token | `335b159a522283767068690d0f711ae1144b4e2a` | 10 / 32 | Purpose/binding, replacement, consume, авторитетное чтение |
| auth-totp | `4408b6fdc04990a228b0d3731246d2120f9e0036` | 16 / 50 | Encryption/AAD, replay counter, factor CAS, enrollment и ключи |
| auth-webauthn | `67aadc6e7eea7155e740be431f62a32282e8f69d` | 16 / 80 | RP/origin/UV, signed assertion, ceremony/counter, admission и регистрация |

Инвентаризация: **225 PHP-файлов / 15 007 строк в src**. Это размер области проверки, не формальное доказательство каждой строки. Граф обязательных зависимостей между этими 16 пакетами ацикличен. `componenta/session` и код ecom в область этого прохода не входят.

## 6. Воспроизводимость и доказательства

Финальный GitHub Actions run: `36320806918`, attempt 5, job `108633082613`, PHP 8.4.26. Workflow: `.github/workflows/audit-snapshot.yml`. Артефакт `auth3-audit-sources`, ID `10933761607`, создан 27.09.2026 в 13:55:40 UTC. SHA-256 ZIP:

`c46bb968544d86f4b43da392996356a8bfc8c5fd29abef13a52d3f621d2eee40`

https://github.com/componenta/auth/actions/runs/36320806918/attempts/5

Manifest содержит точные commit/tree всех пакетов. Общий Composer lock разрешает их совместно через path repositories. Сохранены исходники, resolved dependencies, JUnit, журналы PHPStan и Composer audit. Журналы межпакетных гонок находятся в `verification/storage-races*` внешнего ZIP: внутренний verification.tar.gz создаётся до этого отдельного шага.

После скачивания опубликованного снимка локальные файлы сверены и повторно запущены на PHP 8.4.23: 213 случаев, из них 209 выполнены и 4 production-DB теста сессий пропущены из-за отсутствия локальных серверов; 767 assertions, ошибок и падений нет. PHPStan max успешен везде. Эти четыре пропуска закрыты удалённым прогоном; локальные и удалённые assertions не суммируются между собой.

Для точного повторения использовать source snapshot и Composer lock из артефакта. Повторный composer update на изменившихся dev-ветках уже будет другой сборкой. Red/green журналы дополнительных регрессий приложены к сопровождающему evidence-архиву; положительные контрольные случаи не выдаются за первоначально падавшие тесты.

## 7. Условия внедрения и оставшаяся ответственность приложения

**Обновлять пакеты и DI нужно согласованно.** JWT RefreshHandler и WebAuthnLoginVerifyHandler требуют одиночный обязательный AuthenticationGuardInterface. WebAuthn registration handlers требуют FactorManagementGuard. Issuer использует AuthenticationAdmission; один и тот же содержательный account-admission должен применяться ко всем путям выдачи. Наличие обязательного аргумента не мешает приложению ошибочно передать разрешающую всё политику.

**В актуальном auth-recovery-code уже требуется таблица auth_recovery_code_subject_locks.** До развёртывания adapter необходимо сгенерировать и применить миграцию приложения по текущей reference schema пакета; существующие hashes/batches не требуют конвертации. Не удалять lock rows обычной периодической очисткой. Это ранее опубликованное изменение, а не новая миграция десяти перечисленных коммитов. Рабочая БД и миграции ecom здесь не изменялись и не применялись.

Защита управления факторами теперь не зависит только от identity, но конкретные разрешённые existing factors для первого подключения, замены и восстановления выбирает приложение. Нужны соответствующие политики маршрутов, уведомления об изменении факторов и правила отзыва остальных долговременных credentials. Эти продуктовые действия не реализованы библиотечным gate автоматически.

Распределённое ограничение password/TOTP, доставки писем/SMS и очередей остаётся незакрытой интеграционной задачей. В этом проходе новый распределённый limiter не реализован. OTP-budget не подменяет общий anti-abuse по аккаунту и инфраструктуре. Concrete PasswordResetService должен обеспечивать свои атомарные изменения и отзыв credentials. Stateless access JWT сохраняет предусмотренную TTL-политикой валидность; данная работа не вводит глобальный access-token denylist.

Остаются обязательны испытания реального приложения: HTTPS, trusted proxies/origins, порядок middleware, body limits, cookie flags, маршруты, CORS/CSRF, logger redaction, секреты и ротация ключей, эксплуатация при отказах хранилищ. Primary reads увеличивают нагрузку на writer; архитектура приложения не должна незаметно возвращать эти чтения на eventual-consistency replica.

## 8. Основания проверки и ограничения

Использованы тематические рекомендации OWASP по аутентификации, MFA, сессиям и журналированию, а также документация MySQL по consistent reads. Проверка учитывает server-side enforcement, свежую проверку существующего фактора для чувствительных изменений, одноразовость, короткий срок proof и отсутствие ключевого материала в обычной диагностике. Пунктам ASVS не приписывается индивидуальное соответствие без полной трассировки; соответствие всему L2/L3 не заявляется.

Официальные источники, проверенные 27.09.2026:

- https://owasp.org/projects/asvs
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://dev.mysql.com/doc/refman/8.4/en/innodb-consistent-read.html

Не проводились production pentest ecom, испытание реального replication cluster, физического WebAuthn-устройства, исчерпывающий аудит истории Git на секреты или формальная проверка всех interleavings. Синтетические ключи и изолированные тестовые таблицы не являются пользовательскими данными. Зелёный CI подтверждает перечисленные проверки на указанном наборе, а не полное отсутствие потенциальных уязвимостей.
