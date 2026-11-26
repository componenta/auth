# Шестой независимый проход Componenta Auth — 26 ноября 2026

## Результат

Повторно проверены **17 репозиториев**: 16 действующих Composer-пакетов и
архивный `auth-session-csrf`, указывающий на перенос CSRF в `auth-session-http`.
Заново прочитан **231 production PHP-файл**, публичные контракты, схемы,
значимые тесты и реальные потребители. Области перераспределены между
ревьюерами. Начальный fetch всех репозиториев подтвердил чистые рабочие деревья,
совпадение с upstream и отсутствие внешних изменений после пятого прохода.

**Найден и исправлен один новый дефект WebAuthn:** корректная повторная
аутентификация заранее известного пользователя отклонялась при
`userHandle: null`. Исправление и 13 регрессионных случаев опубликованы в
`fix/auth-audit-2026-11-25`: [457c3683](https://github.com/componenta/auth-webauthn/commit/457c3683defb12e7154b99930a9483660292eb97).
Итоговый diff до коммита одобрили основной и независимый второй ревьюер.
В остальных пакетах новых подтверждённых дефектов не найдено.

После публикации исправления заново выполнены проверки всех 16 пакетов:
**564 выбранных теста, 560 прошли, 4 native DB случая пропущены;
2 578 assertions, 0 failures и 0 errors.** Два исключённых OTP lock-wait случая
в эти 564 не входят. PHPStan max, Composer validate strict и diff-check прошли
во всех 16 пакетах. Composer audit установленного общего набора зависимостей
завершился с кодом 0, без advisories и abandoned packages.

## WebAuthn: ожидаемый пользователь смешивался с ответом authenticator

`WebAuthnReauthenticationOptionsHandler` начинает ceremony для текущего
аутентифицированного пользователя. Его subject сохраняется на сервере, а
список `allowCredentials` строится по принадлежащим ему ключам. При таком
режиме возвращённый `userHandle` может быть `null`; если он предоставлен,
он должен соответствовать владельцу. При discoverable authentication, когда
сервер ещё не знает пользователя, возвращённый handle обязателен.
Это разделение задано в
[W3C WebAuthn §7.2, шаг 6](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).

До исправления `WebAuthnService::validateAuthentication()` передавал
`$response->userHandle` в аргумент библиотеки, означающий **пользователя,
известного серверу до начала ceremony**. Установленный `CheckUserHandle`
при `null` в этом аргументе выбирал discoverable-ветвь и требовал handle
в ответе. В результате действительная P-256 подпись для известного пользователя
отвергалась; HTTP reauthentication возвращал 401 вместо 204.

Теперь ожидаемый handle берётся из сохранённого
`$ceremony->subjectId?->toString()`. Перед проверкой уже сопоставлены владелец
credential и subject ceremony; после библиотеки сохранена дополнительная
проверка владельца возвращённой записи. Проверки подписи, challenge, origin,
user verification, credential ID и одноразовость ceremony остаются в том же пути.

Отдельно сохранён отказ для `userHandle === ''`. Это существенная граница:
vendor в ветви известного пользователя допускает пустую строку как отсутствие
handle, тогда как компонент раньше её отвергал. Простая замена аргумента без
этого условия ослабила бы прежнее поведение. Имена аргументов и публичные
сигнатуры не изменились; PHPDoc и README уточняют контракт.

| Ceremony | Возвращённый handle | Результат |
| --- | --- | --- |
| Известный пользователь | `null` или совпадающий | Допустим при успешных остальных проверках |
| Известный пользователь | Чужой или пустой | Отказ |
| Credential принадлежит другому subject ceremony | Любой | Отказ |
| Discoverable | Совпадающий | Допустим при успешных остальных проверках |
| Discoverable | `null`, пустой или чужой | Отказ |

Классификация: **ложный отказ / протокольная совместимость**. Обход
аутентификации этим дефектом не доказан. Поведенческое исправление занимает
две строки сервиса; новых интерфейсов, зависимостей или схем для него не нужно.

### Подтверждение RED → GREEN

В [AuthenticationUserHandleTest.php](https://github.com/componenta/auth-webauthn/blob/457c3683defb12e7154b99930a9483660292eb97/tests/AuthenticationUserHandleTest.php)
добавлены девять service-сценариев из таблицы и четыре HTTP-сценария:
matching/null handle × непосредственная/отложенная публикация session cookie.
До source-изменений три случая с null handle падали; остальные десять
положительных и отрицательных контрольных случаев уже проходили.

| Проверка | Tests | Assertions | Failures / errors |
| --- | ---: | ---: | --- |
| RED до изменения сервиса | 13 | 121 | 3 / 0 |
| GREEN после исправления | 13 | 155 | 0 / 0 |
| Полная WebAuthn suite в итоговой матрице | 58 | 406 | 0 / 0 |

Использованы настоящий SQLite WebAuthn store, Codec, Validator, Service и
реальные P-256 подписи публичным синтетическим тестовым ключом. Проверяются
сохранность ceremony и counter до commit, однократный commit и отклонение
повтора. HTTP-сценарии проходят настоящие options/verify handlers, общий
issuer/admission/publisher и cookie transport. **Session manager в этих четырёх
тестах — управляемый mock порта:** проверяются вызовы rotation и публикация,
а реальное хранение сессии проверено отдельной композицией ниже. Браузер и
аппаратный authenticator в этих тестах не используются.

## Архитектура и безопасность остальных пакетов

Применены `design-software-interfaces`, `php-best-practices`, `php-testing`
и TDD: сначала наблюдаемое нарушение поддерживаемого контракта и контрольные
сценарии, затем минимальное исправление. Свежие области чтения:

| Область | Source-файлы | Проверенные границы |
| --- | ---: | --- |
| Core и JWT | 59 | Evidence и canonical admission; signature/profile до identity; subject binding; store/CAS/revocation; исключения observers и выдача ответа |
| Password, magic link, TOTP, recovery codes, WebAuthn | 54 | Одноразовость proof; привязка к subject; pre-authentication; факторные guards; crypto/storage; реальные login/reauthentication consumers |
| Session, session database, token, OTP | 62 | Поколения и CAS; свежесть и накопленный evidence; primary reads; tombstones; purpose/binding; бюджеты попыток и история выдачи |
| HTTP, session HTTP, remember-me, два app-adapter | 56 | Владение публикацией; локальная/глобальная отмена; компенсации; cookie/origin/CSRF; request identity и фактическая реализация DI |

Последние исправления checkpoint, remember publisher, token timestamp и
WebAuthn storage revision перечитаны с их потребителями. Token clock fix
дополнительно прошёл отдельный целевой прогон: 3 теста / 23 assertions.
Проверено, что ограничение `used_at` временем создания не меняет исходный
expiry, purpose, binding или одноразовость consume.

Гипотезы, требующие подмены доверенных PHP-объектов, недокументированного
глубокого копирования или атомарности между БД и сетевой доставкой,
не объявлялись уязвимостями без реального пути нарушения контракта.

### Восемь новых проверок совместной работы

Один последовательный локальный probe соединяет реальные SQLite session и
remember managers, восстановление через remember-me, вложенный fallback,
reauthentication и обоих отложенных publishers. Управляется результат
внутреннего authenticator; после выдачи session cookie проверяется через
`resume()`, remember credential — через `rotate()`.

| Сценарий | Наблюдаемый результат |
| --- | --- |
| Контроль без внутренней аутентификации | 204; одна действующая сессия; принимаются generation 2 и новый explicit remember credential |
| Soft failure, затем тот же subject | Тот же результат; общий экземпляр transport state и внешняя сессия сохранены |
| Окончательный отказ | 401; endpoint не вызван; действующих сессий и remember rows нет; credentials не опубликованы |
| Все кандидаты дали soft failure | Та же полная отмена |
| Успешный кандидат с другим subject | Та же полная отмена |
| Logout после постановки двух новых grants в очередь | 204; сессии и remember rows удалены/отозваны; обе cookies с Max-Age=0 |
| Исключение второго кандидата | Исходная ошибка распространяется; endpoint не вызван; неопубликованные grants отозваны |
| Ошибка cache headers при публикации | Исходная ошибка распространяется; все неопубликованные grants компенсированы |

**8/8 PASS, exit 0.** В успешных сценариях две remember rows допустимы:
восстановленный grant и отдельно созданный explicit grant. Контракт не требует
одного persistent grant на сессию. Итоговая cookie содержит именно последний
credential; cancellation/logout/error отзывают оба. Эти восемь проверок
не добавлены к числу 564 PHPUnit/Pest cases и не являются тестом конкуренции.

## Свежая общая матрица

Среда: PHP 8.4.28, PHPUnit 12.5.33, Pest 4.7.8, PHPStan 2.3.7.
Проверки выполнены после публикации WebAuthn fix. PHPStan max анализирует
`src` всех пакетов, а у `auth-session-http` также `tests`.

| Пакет | Выбранные tests | Assertions | Skips | Проверенный HEAD |
| --- | ---: | ---: | ---: | --- |
| auth | 67 | 179 | 0 | `5a3e79b1` |
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
| auth-webauthn | 58 | 406 | 0 | `457c3683` |

Полные SHA, source/tests tree hashes, коды выхода, исходный Git baseline,
результат dependency audit и восемь composition outcomes сохранены в
[AUTH-RECHECK-2026-11-26-PASS6.json](AUTH-RECHECK-2026-11-26-PASS6.json).
Отчёт и навигация публикуются отдельным documentation-only коммитом core;
его исходники и тесты после указанного HEAD не изменяются.

## Выкладка и границы проверки

Для исправления null handle дополнительной миграции нет. При выкладке
накопленных изменений остаётся требование пятого прохода: **сначала добавить
`auth_webauthn_credentials.revision`, затем обновить PHP-код**. Миграции:
[MySQL](https://github.com/componenta/auth-webauthn/blob/457c3683defb12e7154b99930a9483660292eb97/resources/migrations/2026-11-26-credential-revision/mysql-8.4.sql),
[PostgreSQL](https://github.com/componenta/auth-webauthn/blob/457c3683defb12e7154b99930a9483660292eb97/resources/migrations/2026-11-26-credential-revision/postgresql.sql),
[SQLite](https://github.com/componenta/auth-webauthn/blob/457c3683defb12e7154b99930a9483660292eb97/resources/migrations/2026-11-26-credential-revision/sqlite.sql).
Выполнить один раз; при собственном имени таблицы/префиксе адаптировать ALTER.
Production-база в рамках аудита не изменялась.

- Четыре native MySQL/PostgreSQL случая пропущены. SQLite и чтение SQL не
  подтверждают поведение реальных серверов; native WebAuthn ALTER также
  не исполнялся. SQLite migration проверена полной WebAuthn suite.
- Два OTP `LockWaitExpiryTest` случая исключены. Динамическое исследование
  JWT expiry/lock-wait ранее отклонила автоматическая проверка разрешений
  по оценке риска кибербезопасности; оно не возобновлялось и не обходилось.
  Связанное статическое наблюдение остаётся неподтверждённым.
- WebAuthn crypto-тесты не заменяют проверку в браузере с аппаратными ключами.
  Session persistence в четырёх новых handler-тестах заменена портом; реальная
  session/remember persistence проверена отдельными последовательными сценариями.
- Зависимости, схемы и пороги тестов в этом проходе не менялись. Новый mutation
  score не заявляется: production-код session HTTP не менялся.
- Миграция Identity на Config 4 отложена по указанию пользователя.

Предыдущие результаты: [пятый проход](AUTH-RECHECK-2026-11-26-PASS5.md).
