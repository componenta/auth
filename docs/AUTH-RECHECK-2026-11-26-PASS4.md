# Четвёртый независимый проход Componenta Auth — 26 ноября 2026

Последние результаты: [финальная проверка стабильности](AUTH-FINAL-CHECK-2026-11-26.md).

## Результат

Перепроверены все **17 репозиториев** семейства: 16 действующих Composer-пакетов
и `auth-session-csrf`, оставленный как указатель переноса CSRF в
`auth-session-http`. Заново прочитаны **231 PHP-файл production-кода**,
публичные контракты, схемы, значимые тесты и реальные потребители интерфейсов.
Перед работой выполнен fetch всех репозиториев: рабочие деревья были чистыми,
внешних изменений после третьего прохода не было.

Подтверждены и исправлены **два новых дефекта**. Дополнительно согласован
один существующий тест WebAuthn с изменённым моментом публикации credential
и добавлены отрицательные контрактные тесты JWT. Всего добавлены
**27 тестовых случаев**: 3 WebAuthn, 12 session HTTP и 12 JWT.

**Итоговая проверка: 517 выбранных тестов, 513 passed, 4 native DB skips,
2 187 assertions, 0 failures, 0 errors.** Два OTP-кейса ожидания блокировки
исключены и не входят в 517. PHPStan max и Composer validate strict прошли
во всех 16 активных пакетах. Composer audit установленного общего набора
зависимостей завершился с кодом 0; списки advisories и abandoned пусты.

Изменения опубликованы в существующих ветках `fix/auth-audit-2026-11-25`.
Оба production-дефекта имеют отдельные коммиты с RED/GREEN. Ещё два коммита
содержат только тесты. Этот отчёт и машиночитаемая матрица сохраняются
отдельным коммитом документации в `auth`.

| Пакет | Изменение | Опубликованный коммит |
| --- | --- | --- |
| auth-session-http | Единый владелец публикации нового session grant | [ea2ae949](https://github.com/componenta/auth-session-http/commit/ea2ae94912c5bc9751082c0eccce107c6e2ecad3) |
| auth-webauthn | Отклонение невалидного UTF-8 до сериализации registration options | [e331b2dd](https://github.com/componenta/auth-webauthn/commit/e331b2dda62ecd45ca1538c7013a93f0700956cf) |
| auth-webauthn | Завершение transport state в существующем admission test | [97e53aba](https://github.com/componenta/auth-webauthn/commit/97e53abad406951d3474af0c40e8f556c0a286f9) |
| auth-jwt | Отрицательные тесты подписи, профиля, evidence и subject | [f13f83ec](https://github.com/componenta/auth-jwt/commit/f13f83ec6ad7e5c22d23fc3a0e2ffb2a8fd6f8d1) |

## 1. Восстановление сессии и последующий step-up теряли актуальный credential

Пакет: `auth-session-http`. Класс: `AuthSessionGrantPublisher`.

При восстановлении через remember-me middleware создаёт сессию поколения 1,
регистрирует компенсацию выдачи и ставит credential в `CredentialTransportState`.
Последующая успешная reauthentication вращает ту же сессию до поколения 2.
Ранее publisher немедленно записывал credential поколения 2, хотя внешнему
middleware ещё предстояло опубликовать поколение 1.

Последовательная проверка с настоящими SQLite managers, issuer, remember-me
и session middleware показала два нарушения публичного контракта:

| Транспорт | До исправления | После исправления |
| --- | --- | --- |
| SessionCookieTransport | Поздняя запись поколения 1 перезаписывала cookie поколения 2; возвращённый credential не возобновлял сессию | Cookie содержит поколение 2; resume возвращает поколение 2; сессия активна |
| ReplacingPayloadStorage | Замена отменяла старую очередь; её callback отзывал тот же UUID, уже обновлённый до поколения 2 | Публикация завершается общей batch; актуальная сессия не отзывается |

Контрольный сценарий только с remember-me восстановлением продолжает выдавать
рабочее поколение 1. В каждом исправленном сценарии остаётся одна активная
сессия. Проба использует уже подтверждённое evidence на границе issuer;
криптографический verifier step-up в неё не входит. Это доказательство
ошибки композиции и доступности, а не демонстрация обхода аутентификации
через браузер или конкурирующие запросы.

Теперь при существующем `CredentialTransportState` publisher передаёт ему
credential и компенсацию. Внешний владелец публикует очередь в правильном
порядке; последнее поколение формирует итоговый cookie. Без state сохраняется
немедленная запись и установка запрещающих кеширование заголовков.
README явно описывает изменённый момент публикации.

Проверка актуальности grant сохранена. Ошибка чтения request attribute входит
в границу компенсации. Регистрация `onDiscard` находится за пределами catch
непосредственной публикации: callback уже очищенного state может выполниться
синхронно, и его исключение не должно вызывать повторный revoke. Terminal clear
и ошибки отложенной записи либо заголовков компенсируются владельцем state.
Password и magic-link по-прежнему отбрасывают прежнюю очередь до новой выдачи.

[AuthSessionGrantPublisherTest.php](https://github.com/componenta/auth-session-http/blob/ea2ae94912c5bc9751082c0eccce107c6e2ecad3/tests/AuthSessionGrantPublisherTest.php)
проверяет оба транспорта, непосредственную публикацию, ошибки записи и
заголовков, terminal clear, ошибку компенсации, ошибку request attribute
и устаревший grant. Тесты используют объявленные зависимости пакета.

- RED до изменения source: 12 случаев, 5 failures и 2 errors.
- GREEN: те же 12 случаев, 89 assertions.
- Полный пакет: 103 tests, 300 assertions; PHPStan max по src и tests.
- Независимое ревью state-agent и root не выявило блокирующих замечаний.

## 2. Невалидный UTF-8 нарушал контракт ошибок WebAuthn

Пакет: `auth-webauthn`. Класс: `WebAuthnService`.

`username` и `display_name` ограничивались по длине и управляющим символам,
но могли содержать невалидный UTF-8. В частности, form POST способен передать
такую строку. После допуска к управлению факторами она попадала в штатный
Symfony serializer, который выбрасывал `NotEncodableValueException`.
Исключение покидало обработчик вместо предусмотренного ответа 422.

В `assertUserText()` добавлена ранняя проверка корректности UTF-8. Ошибка
становится существующим `InvalidArgumentException` и обрабатывается как
невалидный ввод до создания ceremony. Допустимый Unicode сохраняется.

[RegistrationUserTextTest.php](https://github.com/componenta/auth-webauthn/blob/e331b2dda62ecd45ca1538c7013a93f0700956cf/tests/RegistrationUserTextTest.php)
проходит через настоящий HTTP handler, FactorManagementGuard, origin/CSRF,
WebAuthnService, codec и SQLite. Он проверяет оба повреждённых поля, отсутствие
созданной ceremony при отказе, а также успешные имена с латинскими диакритиками,
кириллицей и японскими символами.

- RED: 3 случая, 2 ошибки настоящего serializer; положительный контроль проходил.
- GREEN: полная WebAuthn suite — 40 tests, 232 assertions; PHPStan max src.

Дефект находится на пути, требующем допуска к управлению факторами.
Обход аутентификации или повышения привилегий не продемонстрирован.

## Дополнительная проверка достоверности тестов

Общий прогон после изменения publisher обнаружил один устаревший сценарий
`LoginAdmissionTest`: request всегда содержал `CredentialTransportState`,
но тест завершал очередь только для настоящего cookie transport. Mock-вариант
ожидал немедленную запись. В fixture теперь безусловно вызывается `apply()`
после handler, как требует контракт владельца state.

Проверки guard, HTTP status, запрет выдачи и записи при отказе, удаление прежнего
credential, counter и одноразовая ceremony сохранены. Независимое ревью
подтвердило, что ожидания не ослаблены: ошибочная отложенная запись в denied
mock-сценариях теперь тоже была бы замечена. После этого полный WebAuthn suite
повторно прошёл на опубликованном коде. Это исправление fixture после изменения
контракта, оно не считается третьим production-дефектом.

В JWT существующий strategy test проверял положительный round trip.
Добавлены [12 отрицательных случаев](https://github.com/componenta/auth-jwt/blob/f13f83ec6ad7e5c22d23fc3a0e2ffb2a8fd6f8d1/tests/JwtStrategyRejectionTest.php)
через настоящий HmacSigner/JwtStrategy:

- повреждённый JWT и подпись другим ключом;
- чужие issuer, audience и token type;
- отсутствие либо невалидный формат authentication evidence;
- подмена subject другой identity со стороны provider.

Все возвращают `InvalidAccessToken` без Identity/evidence. До признания
подписи, профиля и evidence identity lookup не вызывается. В сценарии
подмены provider получает именно subject токена. Время фиксированное и
корректное, проверки expiry/lock-wait не затрагивались. Production-проверки
уже присутствовали и прошли новые тесты; это укрепление регрессионного
покрытия, без заявления о новом security finding. Полная JWT suite: 34/122.

## Архитектура и безопасность: повторно проверенные границы

Применены `design-software-interfaces`, `php-best-practices`, `php-testing`
и TDD для подтверждённых исправлений. Проверка разделялась по независимым
областям, затем изменения publisher и межпакетной fixture получили второе
ревью. Важен наблюдаемый публичный результат: состояние identity, доступность
выданного credential, одноразовость и компенсация, а не только зелёный unit test.

| Область | Проверенные контракты |
| --- | --- |
| Core и DI | Evidence перед успехом; окончательный admission; недвусмысленный результат; изоляция observers; exact-class events; получение текущего состояния из переданного request |
| HTTP и session HTTP | Общий владелец публикации; pending и active batch; terminal clear; cookie replacement; no-store; origin/CSRF; привязка assurance к актуальному subject и поколению |
| Session, database, token, remember-me | Expiry и предыдущие calendar/subsecond регрессии; primary reads; CAS и одноразовое потребление; rotation/revoke; точная компенсация выдачи и logout после восстановления |
| Password, OTP, magic link | Purpose/binding; обязательный admission; явное evidence; бюджет попыток и ошибки доставки; отмена конкретного неопубликованного grant |
| TOTP, recovery codes, WebAuthn | Валидация до изменения состояния; keyring; CAS факторов; одноразовость; subject/RP/origin; counter; ceremony; хранение результата штатным DB-адаптером |
| JWT | Заданный signer/profile; issuer/audience/type; UUID/evidence; refresh family и обычный replay lifecycle; компенсация после rotation |

Кроме двух описанных production-дефектов новых подтверждённых ошибок
в разрешённой области этого прохода не получено. Заимствование вложенных
объектов в Context/Claims и отсутствие гарантии атомарной внешней доставки
оценивались по существующим контрактам. Спекулятивные изменения rollback
или публичных manager API не добавлялись.

## Итоговая матрица

Runtime: PHP 8.4.28, PHPUnit 12.5.33 / Pest 4.7.8, PHPStan 2.3.7.
Все 16 suites выполнены через общий Composer path autoload после двух
production-исправлений. После test-only изменений повторены полные suites
затронутых WebAuthn и JWT и их остальные gates. Показатели ниже относятся
к проверенным опубликованным SHA; последующий коммит отчёта в auth не меняет
source и tests.

| Пакет | Проверенный SHA | Selected | Passed | Skipped | Assertions |
| --- | --- | ---: | ---: | ---: | ---: |
| auth | `1f4fd80d` | 67 | 67 | 0 | 179 |
| auth-app | `df172cdc` | 11 | 11 | 0 | 22 |
| auth-http | `787b8588` | 41 | 41 | 0 | 196 |
| auth-jwt | `f13f83ec` | 34 | 34 | 0 | 122 |
| auth-magic-link | `30abe166` | 15 | 15 | 0 | 80 |
| auth-otp | `630b2609` | 41 | 41 | 0 | 334 |
| auth-password | `8e04a0ec` | 14 | 14 | 0 | 65 |
| auth-recovery-code | `448f7913` | 15 | 15 | 0 | 59 |
| auth-remember-me | `7b60d8a9` | 18 | 18 | 0 | 121 |
| auth-session | `cdc21060` | 16 | 16 | 0 | 53 |
| auth-session-app | `5668a08e` | 13 | 13 | 0 | 25 |
| auth-session-database | `c715b274` | 43 | 39 | 4 | 265 |
| auth-session-http | `ea2ae949` | 103 | 103 | 0 | 300 |
| auth-token | `f30fed77` | 14 | 14 | 0 | 44 |
| auth-totp | `eb2cce83` | 32 | 32 | 0 | 90 |
| auth-webauthn | `97e53aba` | 40 | 40 | 0 | 232 |
| **Всего** | | **517** | **513** | **4** | **2 187** |

PHPStan max по src — 16/16; для session HTTP дополнительно проверены tests.
Composer validate strict и diff check — 16/16. Composer audit относится
к установленному общему набору зависимостей, а не ко всем возможным будущим
вариантам их разрешения.

Обязательный Infection 0.35.12 для изменённого session HTTP прошёл
с неизменными порогами 80/80: **273 мутанта, 248 killed, 25 escaped,
0 uncovered, 0 timeouts; MSI и Covered MSI 90,84%**.
100% Mutation Code Coverage относится к сгенерированным мутантам
и не означает 100% покрытия строк.

Полные SHA, Git trees, статусы gates, состав skips, исключения и коммиты:
[AUTH-RECHECK-2026-11-26-PASS4.json](AUTH-RECHECK-2026-11-26-PASS4.json).

## Границы результата

Четыре native DB-кейса остаются пропущенными: session lifecycle и одноразовый
pre-auth для MySQL 8.4 и PostgreSQL. Поведенческие проверки хранения выполнены
на SQLite. Ранее среда запретила создание PostgreSQL socket; это ограничение
не обходилось и native-серверы заново не поднимались.

Два случая `auth-otp/tests/LockWaitExpiryTest.php` исключены обязательным
фильтром. Ранее автоматический контроль остановил динамическое исследование
JWT expiry/lock-wait с причиной возможного cybersecurity risk. Этот вид работы
не возобновлялся и не передавался другому исполнителю. Статическое наблюдение
о чтении времени до ожидания блокировки остаётся неподтверждённым;
оно не отмечается как доказанная или исправленная уязвимость.

Identity и переход на Config 4 остаются отложенными по указанию пользователя.
В этом проходе не менялись зависимости, SQL-схемы, настройки тестирования
и пороги. Аудит не является доказательством отсутствия любых будущих дефектов;
его проверяемый результат — описанные исправления, тесты и границы выполнения.

Предыдущие результаты: [первый аудит](AUTH-AUDIT-2026-11-25.md),
[второй проход](AUTH-RECHECK-2026-11-26.md),
[третий проход](AUTH-RECHECK-2026-11-26-PASS3.md).
