# Пятый независимый проход Componenta Auth — 26 ноября 2026

Последние результаты: [финальная проверка стабильности](AUTH-FINAL-CHECK-2026-11-26.md).

## Результат

Перепроверены **17 репозиториев**: 16 активных Composer-пакетов и архивный
`auth-session-csrf`, оставленный указателем на перенос CSRF в `auth-session-http`.
Заново прочитан **231 production PHP-файл**, публичные контракты, SQL-схемы,
значимые тесты и реальные потребители. В начале выполнен fetch всех репозиториев:
рабочие деревья были чистыми; внешних изменений после четвёртого прохода не было.

**Подтверждены и исправлены четыре новых дефекта.** Каждый получил отдельный
коммит с регрессионной проверкой RED → GREEN. Добавлены **34 тестовых
случая**. Исправления прошли повторное ревью и опубликованы в
`fix/auth-audit-2026-11-25`; для `auth-remember-me` такая ветка создана от его
исходного `main`. Все 16 активных пакетов теперь имеют audit-ветку.

**Итог: выбран 551 тест; 547 прошли, 4 native DB случая пропущены;
2 423 assertions, 0 failures и 0 errors.**
Два исключённых OTP lock-wait случая в это число не входят. PHPStan max,
Composer validate strict и diff-check прошли во всех 16 активных пакетах.
Composer audit общего установленного набора зависимостей завершился с кодом 0.

| Пакет | Исправление | Опубликованный коммит |
| --- | --- | --- |
| auth-http | Локальная отмена неуспешного кандидата при вложенной аутентификации | [fac545c6](https://github.com/componenta/auth-http/commit/fac545c6ca7f2faf8dd752c1475d9b48701f34f9) |
| auth-remember-me | Публикация нового remember grant через общего владельца | [ace71d9d](https://github.com/componenta/auth-remember-me/commit/ace71d9d5a58fd5f9c1f1533beda5f994496ec71) |
| auth-token | Корректное потребление после перевода часов назад | [4ef6afff](https://github.com/componenta/auth-token/commit/4ef6afff101a9c1c1c8d85b388c116caf36de1f5) |
| auth-webauthn | Успешный UPDATE ключа с нулевым счётчиком на changed-row драйвере | [31b7d655](https://github.com/componenta/auth-webauthn/commit/31b7d65514f12a1393cea121fea1f6b56ba88d26) |

## 1. Вложенный soft failure отзывал внешнюю сессию

В `AuthenticationMiddleware` промежуточный отказ кандидата вызывал глобальный
`CredentialTransportState::discardQueued()`. При вложенных middleware это
отменяло уже успешное внешнее восстановление через remember-me: отзывалась
сессия и удалялись ожидающие публикации cookies. Следующий кандидат мог успешно
подтвердить того же субъекта, после чего downstream получал старый `AuthSession`,
хотя соответствующая сессия уже была отозвана.

Последовательная проба использует настоящие SQLite session/remember managers,
issuer и middleware с управляемым результатом внутреннего authenticator.
Контроль возвращал HTTP 204, две cookies и одну активную сессию. До исправления
вложенный soft failure с последующим успехом возвращал HTTP 204 с присутствующим,
но уже неактуальным `AuthSession`, без cookies и без активной сессии.

Исправление сохраняет **тот же экземпляр transport state** и прежнего владельца.
Перед каждым кандидатом создаётся внутренний checkpoint — одноразовое действие
отмены. Soft failure удаляет только ещё ожидающую работу, зарегистрированную
после этой точки. Монотонные номера регистраций не сбрасываются; отмена не
восстанавливает snapshot и не возвращает ранее глобально отменённую работу.

Callbacks отделяются до вызова, выполняются в обратном порядке; после обработки
всех выбранных callbacks пробрасывается первая ошибка. Повторная отмена ничего
не делает. Окончательный отказ, несовпадение identity, explicit discard/clear и
компенсация владельца при исключении сохраняют глобальную семантику. При
возвращении callbacks из active batch сохраняются их номера, без переиндексации.

Реализация и публичные регрессионные сценарии проверены root и независимым
state reviewer. В HTTP добавлено 15 тестовых случаев. Проверяется
наблюдаемый результат и сохранность внешней работы через публичный API.
RED до source-изменений: 15 случаев / 108 assertions, два поведенческих failure
и семь ошибок отсутствующего checkpoint API; шесть контрольных случаев
уже проходили. Целевой GREEN: 15 случаев / 139 assertions.

## 2. Новый remember-me grant перезаписывался старой очередью

`RememberMeGrantPublisher` немедленно записывал новую cookie, даже когда внешний
middleware уже владел отложенной публикацией remember-me rotation. При выдаче
нового persistent grant для той же восстановленной текущей сессии outer owner
затем публиковал старую очередь и перезаписывал новую cookie.

В реальной последовательной цепочке requested TTL 600 секунд превращался в
итоговый Max-Age 3600; новый credential не доставлялся. После исправления
публикуется новый credential с Max-Age 600, который можно использовать для
следующей rotation; текущая сессия остаётся действующей. Контроль без новой
выдачи по-прежнему получает прежний срок 3600 секунд.

При наличии `CredentialTransportState` publisher теперь передаёт ему grant и
revocation callback. Владелец завершает публикацию по порядку. Без state остаётся
непосредственная запись. Ошибка чтения request attribute компенсируется; callback
уже очищенного state не вызывается повторно после его собственного исключения.
README описывает изменённый момент публикации.

Добавлены 11 случаев: ожидаемое последнее значение cookie и TTL, immediate mode,
ошибки записи/заголовков в обоих режимах, clear до/после очереди, discard,
однократная компенсация и ошибка request attribute. RED: 11 случаев,
6 failures + 2 errors; GREEN: 11 случаев / 55 assertions.

## 3. Одноразовый токен нельзя было использовать после коррекции часов

`DatabaseTokenManager::find()` считал ранее выданный неистёкший токен действующим
после небольшого перевода часов назад. `consume()` записывал `used_at` раньше
`created_at`, затем конструктор `TokenRecord` выбрасывал исключение, и транзакция
откатывалась. Публичный контракт не определяет создание как not-before; поля
not-before у токена нет. Реальный потребитель этого API — `MagicLinkStrategy`.

Теперь только сохранённое и возвращённое `used_at` ограничивается снизу
временем создания. **Проверки expiry в SELECT и условном UPDATE продолжают
использовать реальные текущие часы**; первоначальный срок действия не меняется.
Условия purpose, binding, hash, unused и единственного победителя сохранены.

Три теста на реальном SQLite и последовательном FrozenClock проверяют коррекцию
назад, обычное движение времени и неизменность исходного expiry. Replay запрещён
как сразу, так и после восстановления часов. RED: 3 случая / 14 assertions /
1 error. GREEN всей token suite: 17 случаев / 67 assertions.

## 4. WebAuthn ошибочно отвергал успешное обновление ключа

`DatabaseWebAuthnStore::updateCredential()` считал успехом только row count 1.
Подлинный authenticator может оставлять signature counter равным нулю. Если
JSON credential и timestamp не изменились, новый допустимый UPDATE не меняет
значений строки. MySQL по умолчанию считает фактически изменённые строки и
возвращает 0. Сервис поэтому отказывал после расходования ceremony.

Первичные источники:
[MySQL 8.4 UPDATE](https://dev.mysql.com/doc/refman/8.4/en/update.html),
[W3C WebAuthn §6.1.1](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter).
В установленном Cycle проверены путь UPDATE → execute → PDO rowCount и
отсутствие FOUND_ROWS среди стандартных опций соединения.

В тот же условный UPDATE добавлено `revision = revision + 1`. Совпавшая строка
всегда меняется; проверки credential hash, subject и ожидаемого counter остаются
частью записи. Лишнего SELECT после неуспешного UPDATE нет: старый transaction
snapshot не доказывает, что текущий CAS совпал. Публичные DTO/API не расширены.

### Обязательная миграция перед выкладкой

В таблицу `auth_webauthn_credentials` добавлен внутренний столбец `revision`
с `NOT NULL DEFAULT 0`. **Сначала применить миграцию, затем выкладывать PHP-код.**
Готовы миграции для [MySQL](https://github.com/componenta/auth-webauthn/blob/31b7d65514f12a1393cea121fea1f6b56ba88d26/resources/migrations/2026-11-26-credential-revision/mysql-8.4.sql),
[PostgreSQL](https://github.com/componenta/auth-webauthn/blob/31b7d65514f12a1393cea121fea1f6b56ba88d26/resources/migrations/2026-11-26-credential-revision/postgresql.sql)
и [SQLite](https://github.com/componenta/auth-webauthn/blob/31b7d65514f12a1393cea121fea1f6b56ba88d26/resources/migrations/2026-11-26-credential-revision/sqlite.sql).
При собственном имени таблицы/префиксе Cycle имя в ALTER нужно адаптировать;
миграция выполняется один раз. Старый код совместим с добавленным default-столбцом.
Production-база в этом аудите не изменялась.

RED: 4 случая / 12 assertions / 1 ожидаемый failure. GREEN: 5 случаев /
19 assertions, включая миграцию существующей SQLite-таблицы без потери ключа.
Отрицательные контроли: stale counter, чужой subject, удалённый credential.
Регрессия выполняет реальный SQL на SQLite через общий драйверный fixture,
считающий изменившиеся строки; fixture сравнивает все столбцы и не знает о
`revision`. **Это не native MySQL test.** Native миграции MySQL/PostgreSQL не
выполнялись.

## Архитектура, безопасность и область доказательств

Применены `design-software-interfaces`, `php-best-practices`, `php-testing`
и TDD. Пакеты перераспределены между ревьюерами; исправления прошли второе
ревью до коммита. Проверены ownership публикации, компенсации и повторные
вызовы, одноразовость proof, subject/evidence binding, admission перед выдачей,
первичные чтения, CAS, поколения и отзыв сессий, JWT signature/profile,
origin/CSRF, изоляция observers и request-scoped DI.

В core, JWT, password, magic-link, TOTP, recovery codes, session, session database,
OTP, session HTTP и двух app-adapters новых подтверждённых дефектов не найдено.
Гипотезы, требующие произвольного подменённого trusted DTO либо недокументированной
гарантии, не объявлялись уязвимостями. Четыре исправления устраняют реальные
нарушения lifecycle/композиции/доступности; обход аутентификации ими не доказан.

## Свежая общая проверка

Среда: PHP 8.4.28, PHPUnit 12.5.33, Pest 4.7.8, PHPStan 2.3.7.
Выполнены полные выбранные suites всех 16 пакетов после четырёх опубликованных
исправлений, PHPStan max, Composer validate strict и diff-check. Для session HTTP
PHPStan проверяет и src, и tests; для остальных пакетов — src.

| Пакет | Выбранные tests | Assertions | Skips | Проверенный HEAD |
| --- | ---: | ---: | ---: | --- |
| auth | 67 | 179 | 0 | `ff53b5e4` |
| auth-app | 11 | 22 | 0 | `df172cdc` |
| auth-http | 56 | 335 | 0 | `fac545c6` |
| auth-jwt | 34 | 122 | 0 | `f13f83ec` |
| auth-magic-link | 15 | 80 | 0 | `30abe166` |
| auth-otp | 41 | 334 | 0 | `630b2609` |
| auth-password | 14 | 65 | 0 | `8e04a0ec` |
| auth-recovery-code | 15 | 59 | 0 | `448f7913` |
| auth-remember-me | 29 | 176 | 0 | `ace71d9d` |
| auth-session | 16 | 53 | 0 | `cdc21060` |
| auth-session-app | 13 | 25 | 0 | `5668a08e` |
| auth-session-database | 43 | 265 | 4 | `c715b274` |
| auth-session-http | 103 | 300 | 0 | `ea2ae949` |
| auth-token | 17 | 67 | 0 | `4ef6afff` |
| auth-totp | 32 | 90 | 0 | `eb2cce83` |
| auth-webauthn | 45 | 251 | 0 | `31b7d655` |

Полные SHA, source/tests tree hashes, коды выхода, baseline и результаты audit:
[AUTH-RECHECK-2026-11-26-PASS5.json](AUTH-RECHECK-2026-11-26-PASS5.json).
Отчёт добавляется отдельным documentation-only коммитом; исходники и тесты
core после указанного проверенного HEAD не изменяются.

## Оставшиеся границы проверки

- Четыре native MySQL/PostgreSQL случая пропущены. SQLite и чтение схем не
  подтверждают поведение настоящих серверов, включая новый WebAuthn ALTER.
- Два OTP `LockWaitExpiryTest` случая исключены. Ранее остановленное динамическое
  исследование JWT expiry/lock-wait не возобновлялось и не обходилось другим
  инструментом; связанное статическое наблюдение остаётся неподтверждённым.
- Зависимости и пороги тестов не менялись. Новый mutation score не заявляется:
  production-код session HTTP в этом проходе не менялся.
- Миграция Identity на Config 4 отложена по указанию пользователя.
