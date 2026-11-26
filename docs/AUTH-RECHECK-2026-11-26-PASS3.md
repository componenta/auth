# Третий независимый проход Componenta Auth — 26 ноября 2026

Более поздние результаты и два дополнительных production-исправления:
[пятый независимый проход](AUTH-RECHECK-2026-11-26-PASS5.md).
Приведённые ниже показатели относятся к третьему проходу.

## Результат

Перепроверены все 17 репозиториев семейства: 16 действующих Composer-пакетов
и `auth-session-csrf`, содержащий указатель переноса CSRF в
`auth-session-http`. Заново прочитаны все 231 PHP-файл production-кода,
выбранные контрактные тесты, схемы и реальные потребители интерфейсов.

Подтверждены и исправлены **четыре новых дефекта**. Каждый исправлен отдельным
коммитом с выполненным RED/GREEN и опубликован в существующей ветке
`fix/auth-audit-2026-11-25`. Добавлены 12 тестовых случаев. Отдельный
заключительный коммит содержит этот отчёт, машиночитаемый результат проверок
и ссылки из предыдущих отчётов.

**Итоговая общая проверка опубликованного кода: 490 выбранных тестов,
486 passed, 4 native DB skips, 2 039 assertions, 0 failures, 0 errors.**
Два OTP-кейса ожидания блокировки исключены и не входят в число 490.
PHPStan max, Composer validate strict и проверка diff прошли для всех
16 активных пакетов. Composer audit установленного набора зависимостей
завершился с кодом 0: списки advisories и abandoned пусты.

Это продолжение [первого аудита](AUTH-AUDIT-2026-11-25.md) и
[второго прохода](AUTH-RECHECK-2026-11-26.md). Результаты прежних прогонов
не использовались как доказательство текущего состояния.

## Подтверждённые дефекты и исправления

### 1. Продление активности могло сократить срок сессии

Пакет: `auth-session-database`.
Класс: `DatabaseAuthSessionManager`.
Опубликованный коммит:
[c715b274](https://github.com/componenta/auth-session-database/commit/c715b274694f4a34dd4d051b7384ae3daf3880b0).

`touch()` и `rotate()` без новой policy восстанавливали длительность
idle window вычитанием целых Unix timestamps. Когда предыдущая активность
ограничивала срок абсолютным expiry, оставшийся интервал мог содержать
дробную часть секунды. Следующее продление теряло эту часть и сокращало
уже выданный срок.

Воспроизведение через публичные API, SQLite и FrozenClock:

| Действие | Время / результат |
| --- | --- |
| Создать сессию с idle 10 s и absolute 11 s | `00:00:00.900000` |
| Обновить активность | `00:00:02.100000` |
| Получить ограниченный абсолютным сроком idle expiry | `00:00:11.900000` |
| Повторить touch либо rotate в `00:00:02.200000` | До исправления expiry становился `00:00:11.200000` |

Исправление сохраняет точную прошедшую длительность в UTC, включая
микросекунды. Ограничение абсолютным сроком и условные обновления поколения
сохранены. Это ошибка жизненного цикла и доступности сессии.

Независимая проверка первоначального патча выявила регрессию:
`DateTime::diff()` может выразить 31 день как календарный месяц.
При переносе такого интервала с января на февраль получалось 1 марта
вместо 4 марта. До публикации добавлены три RED-сценария и исправлена
нормализация интервала: годы/месяцы преобразуются в общее число дней,
сохраняются часы, минуты, секунды и микросекунды. Эта промежуточная версия
не публиковалась и не считается отдельным дефектом продукта.

Регрессии в
[DatabaseAuthSessionManagerTest.php](https://github.com/componenta/auth-session-database/blob/c715b274694f4a34dd4d051b7384ae3daf3880b0/tests/DatabaseAuthSessionManagerTest.php):
`testActivityRenewalPreservesTheAbsoluteExpiryCap` и
`testActivityRenewalPreservesElapsedTimeoutAcrossCalendarMonths`.
Оба сценария проверяют touch, PrivilegeChange и SecurityEvent, а также
resume непосредственно перед expiry и отказ точно на границе.
Итоговый suite пакета: 43 selected, 39 passed, 4 skipped, 265 assertions.

### 2. Необязательный User-Agent срывал выдачу сессии

Пакет: `auth-session-http`.
Класс: `BasicSessionMetadataExtractor`.
Опубликованный коммит:
[7fe52b43](https://github.com/componenta/auth-session-http/commit/7fe52b43e6a909c54b519dacc01094b953cd99fb).

Extractor принимал ограниченную по длине строку User-Agent без запрещённых
управляющих байтов, но не проверял UTF-8. Такой запрос принимался Nyholm
PSR-7, после чего штатный SQL-адаптер завершал кодирование metadata
с `JsonException`. Реальные login handlers извлекают metadata после
consume pre-auth; поэтому необязательное поле могло сорвать попытку входа
после расходования доказательства.

Публичное воспроизведение проверено и отдельно, и в связке
Nyholm request → BasicSessionMetadataExtractor → AuthenticatedSessionIssuer /
AuthenticationAdmission → DatabaseAuthSessionManager / SQLite.
До исправления происходила ошибка JSON; после него сессия выдаётся
и возобновляется.

Добавлена проверка UTF-8 через существующий PCRE. Невалидный необязательный
User-Agent пропускается; валидные ASCII, многобайтовый UTF-8 и прямой IP
сохраняются. Новая зависимость не нужна.

Переносимые регрессии:
[BasicSessionMetadataExtractorTest.php](https://github.com/componenta/auth-session-http/blob/7fe52b43e6a909c54b519dacc01094b953cd99fb/tests/BasicSessionMetadataExtractorTest.php).
Пакетные тесты не получили скрытой зависимости от тестов SQL-адаптера.
Классификация — устойчивость обработки входных данных отдельного запроса;
обход аутентификации не обнаружен.

### 3. Компенсация пропускала ошибки между аутентификацией и downstream

Пакет: `auth-http`.
Класс: `AuthenticationMiddleware`.
Опубликованный коммит:
[787b8588](https://github.com/componenta/auth-http/commit/787b8588ea9e78e1637232af26787ce27378ef8f).

Middleware компенсировал выданные credentials при исключении из
authenticator и при исключении downstream handler. Между этими блоками
он согласовывал результат и обновлял атрибуты request вне области cleanup.
Если пользовательский request collaborator выбрасывал исключение на этом
этапе, публикация не происходила, а зарегистрированный `onDiscard`
оставался невызванным.

Публичный RED дал: downstream не вызван, credential не опубликован,
pending work остаётся, число компенсаций равно 0. Это противоречило
обещанию README компенсировать выданные, но неопубликованные credentials.

Одна область `try/catch` теперь охватывает обработку candidate,
согласование результата, request decoration и downstream. Ответственность
сохранена за middleware, создавшим transport state. Заимствовавший состояние
вложенный middleware не выполняет чужую компенсацию; публикация по-прежнему
использует собственную область обработки ошибок в `CredentialTransportState`.

[AuthenticationMiddlewareCleanupTest.php](https://github.com/componenta/auth-http/blob/787b8588ea9e78e1637232af26787ce27378ef8f/tests/AuthenticationMiddlewareCleanupTest.php)
проверяет owner, borrower и nested failure, отсутствие публикации,
сохранение исходного исключения и компенсацию ровно один раз.
До исправления падал owner-case; два контроля уже проходили.
После исправления полный suite: 41 тест, 196 assertions.

Это нарушение контракта при сбое доверенного расширения request.
Штатный Nyholm request в обычном режиме на этих атрибутах не падает;
подтверждённой удалённой уязвимостью случай не классифицируется.

### 4. Один subject мог одновременно обозначать успех и отказ

Пакет: `auth`.
Класс: `AuthenticationResult`.
Опубликованный коммит:
[271ebc4c](https://github.com/componenta/auth/commit/271ebc4c16dd60067b37b659bd9ff1a8e2ef54e1).

Публичный union-тип допускал объект, реализующий одновременно
`IdentityInterface` и `DeniedReasonInterface`. Конструктор сначала
проверял denial и принимал такой результат без evidence. Потребители
`Authenticator` и `EventingAuthenticator` сначала проверяли identity
и воспринимали тот же результат как успешный.

Нарушалось явное обещание: успешная аутентификация всегда требует
`AuthenticationEvidence`. RED прошёл через обычный constructor и реальный
`Authenticator`, без Reflection или доступа к приватному состоянию.

Минимальный guard конструктора запрещает неоднозначный subject.
README фиксирует единственность исхода. Проверка:
[AuthenticationResultTest.php](https://github.com/componenta/auth/blob/271ebc4c16dd60067b37b659bd9ff1a8e2ef54e1/tests/AuthenticationResultTest.php),
`testAmbiguousSubjectCannotReachTheCallerAsSuccessWithoutEvidence`.
Итоговый core suite: 67 тестов, 179 assertions.

Это корректность контракта доверенного расширения. Изменение уточняет
допустимость аргумента, сохраняя сигнатуру конструктора; эксплуатация
недоверенным удалённым клиентом не доказана.

## Архитектура и безопасность остальных областей

Применены `design-software-interfaces`, `php-best-practices`,
`php-testing` и TDD. Проверка разделялась по владельцам состояния,
затем результаты сопоставлялись с реальными потребителями. Исправления
прошли отдельный review перед публикацией.

| Область | Повторно проверенные инварианты |
| --- | --- |
| Core и DI | Обязательное evidence; admission перед успехом; изоляция ошибок observers; exact-class events; текущее состояние берётся из переданного request; Context владеет верхним уровнем карты |
| HTTP и CSRF | Общий владелец публикации; terminal clear; LIFO cleanup; no-store headers; cookie flags; origin policy; проверка активного поколения/subject при изменении факторов |
| Сессии и remember-me | Точность expiry; одноразовые pre-auth grants; rotation/CAS; отзыв и tombstones; primary reads; привязка remember-me к сессии и компенсация конкретного поколения |
| Password, OTP, magic link | Проверка binding/purpose и результата authenticator; обязательный финальный admission; явное evidence; история бюджета OTP после отзыва и ошибки доставки; отмена точного неопубликованного grant |
| TOTP и recovery codes | Валидация до изменения состояния; шифрование и keyring; CAS конкретного фактора; одноразовость; замена batch; подготовка ответа до необратимой замены |
| WebAuthn | RP/origin; криптографическая проверка; subject и user handle; одноразовая ceremony; counter CAS; browser binding login; сохранение обновлённого authentication record штатным DB-адаптером при commit |
| JWT | Заданный signer/profile; issuer/audience/type; UUID и evidence; сохранение evidence при refresh; абсолютный срок family; обычный replay lifecycle; компенсация после rotation |

В `auth-app`, `auth-jwt`, `auth-magic-link`, `auth-otp`,
`auth-password`, `auth-recovery-code`, `auth-remember-me`,
`auth-session`, `auth-session-app`, `auth-token`, `auth-totp`
и `auth-webauthn` этот проход не дал нового подтверждённого дефекта.

Не добавлялись необоснованные гарантии. В частности:

- README явно допускает заимствование вложенных объектов в Context/Claims;
  это не требование рекурсивного копирования каждого DTO.
- У `TokenRequestProcessor` и sender нет обещания атомарной доставки.
  Исключение может возникнуть после фактической отправки; слепой consume
  изменил бы семантику одноразового токена. Это вопрос контракта интеграции,
  а не доказанное нарушение с готовым безопасным rollback.
- WebAuthn reauthentication согласованно использует subject-bound ceremony.
  Изменение её в session-bound протокол требует отдельного решения.
- Ошибка доставки HTTP после замены recovery batch или фактора не даёт
  основания восстанавливать старый batch либо широко отзывать новые
  параллельные изменения.
- Прикладные ограничения частоты password/TOTP и доставки не заменяются
  внутренним бюджетом OTP; новый распределённый limiter в этот патч
  не включался.

Identity и переход на Config 4 остаются отложенными по указанию пользователя.
В этом проходе не менялись Composer constraints, SQL-схемы, настройки
PHPUnit/Infection и пороги тестирования.

## Итоговая матрица на опубликованном коде

PHP 8.4.28, PHPUnit 12.5.33 / Pest 4.7.8, PHPStan 2.3.7.
Все 16 suites заново запущены вместе через общий Composer path autoload
после четырёх исправлений. SHA ниже обозначают проверенный код; последующий
коммит документации в `auth` его не меняет.

| Пакет | Проверенный SHA | Selected | Passed | Skipped | Assertions |
| --- | --- | ---: | ---: | ---: | ---: |
| auth | `271ebc4c` | 67 | 67 | 0 | 179 |
| auth-app | `df172cdc` | 11 | 11 | 0 | 22 |
| auth-http | `787b8588` | 41 | 41 | 0 | 196 |
| auth-jwt | `250895cc` | 22 | 22 | 0 | 71 |
| auth-magic-link | `30abe166` | 15 | 15 | 0 | 80 |
| auth-otp | `630b2609` | 41 | 41 | 0 | 334 |
| auth-password | `8e04a0ec` | 14 | 14 | 0 | 65 |
| auth-recovery-code | `448f7913` | 15 | 15 | 0 | 59 |
| auth-remember-me | `7b60d8a9` | 18 | 18 | 0 | 121 |
| auth-session | `cdc21060` | 16 | 16 | 0 | 53 |
| auth-session-app | `5668a08e` | 13 | 13 | 0 | 25 |
| auth-session-database | `c715b274` | 43 | 39 | 4 | 265 |
| auth-session-http | `7fe52b43` | 91 | 91 | 0 | 211 |
| auth-token | `f30fed77` | 14 | 14 | 0 | 44 |
| auth-totp | `eb2cce83` | 32 | 32 | 0 | 90 |
| auth-webauthn | `0f27eb36` | 37 | 37 | 0 | 224 |
| **Всего** | | **490** | **486** | **4** | **2 039** |

PHPStan max выполнялся по `src`, а для `auth-session-http` —
по `src tests`, как требует пакет. Везде ноль ошибок.
Composer validate strict прошёл 16/16. Composer audit завершился успешно
для установленного общего набора зависимостей; это не гарантия отсутствия
неизвестных уязвимостей во всех будущих вариантах разрешения зависимостей.

Обязательная проверка Infection для изменённого `auth-session-http`
выполнена с исходной конфигурацией и порогами 80/80: **262 мутанта,
237 killed, 25 escaped, 0 uncovered, 0 timeouts; MSI и Covered MSI 90,46%**.
Показатель Mutation Code Coverage 100% относится к сгенерированным мутантам
и не означает 100% покрытия строк.

Полные SHA, деревья, машинные статусы gates, native skips и исключения:
[AUTH-RECHECK-2026-11-26-PASS3.json](AUTH-RECHECK-2026-11-26-PASS3.json).

## Границы проверки

Четыре native DB-кейса не выполнены: session lifecycle и одноразовый pre-auth
для MySQL 8.4 и PostgreSQL. Они отмечены как skips, а не passes.
Ранее попытка запуска локального PostgreSQL была остановлена ограничением
среды на создание socket (`Operation not permitted`); обход этого
ограничения не предпринимался. Выполнены обычные SQLite-сценарии.

Два кейса `auth-otp/tests/LockWaitExpiryTest.php` исключены.
Ранее автоматический контроль выполнения остановил динамическое
исследование JWT expiry/lock-wait по причине возможного cybersecurity risk.
Эта область не возобновлялась и не передавалась другому исполнителю.
Наблюдение о чтении времени до ожидания блокировки остаётся
неподтверждённым статическим замечанием; исправленным либо доказанным
дефектом оно не объявляется.

Результаты подтверждают перечисленные контракты и выполненные проверки
на указанных версиях. Они не доказывают отсутствие всех возможных
уязвимостей или интеграционных ошибок.

## Публикация и воспроизводимость

Все четыре исправления опубликованы отдельными коммитами в
`fix/auth-audit-2026-11-25`. Для каждого проверено равенство локального
проверенного Git tree и дерева опубликованного коммита. Обновление refs
выполнено с проверкой ожидаемого родителя, без force push.

В начале и конце прохода выполнен fetch всех 17 репозиториев.
Перед заключительным коммитом документации все рабочие деревья чистые
и имеют расхождение с upstream 0/0. Audit-ветки существуют в 15 активных
пакетах; неизменённый `auth-remember-me` и migration pointer
`auth-session-csrf` остаются на `main`.

Для воспроизведения из каталога соответствующего пакета:

```sh
php vendor/bin/phpunit --bootstrap vendor/autoload.php --colors=never
php vendor/bin/phpstan analyse src --level=max --no-progress
composer validate --strict --no-interaction
```

Для `auth-app` используется Pest. Для `auth-session-http` анализ включает
`src tests`; проверка мутациями выполняется штатной командой
`composer mutation`. При повторении именно этого ограниченного прогона
OTP добавляет фильтр `/^(?!.*LockWaitExpiryTest).*$/`.
Команды требуют объявленных зависимостей пакетов и совместимых веток Auth 3.

Локальные журналы этого прохода сохранены под
`implementation/pass3-*.md`, а итоговые JUnit, Composer и PHPStan логи —
под `implementation/pass3/final/`. Публичные регрессионные тесты находятся
в четырёх опубликованных коммитах, перечисленных выше.
