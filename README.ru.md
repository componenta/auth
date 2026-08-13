# Componenta Auth

Контракты аутентификации и PSR-7/PSR-15 компоненты для приложений Componenta на PHP 8.4+.

Middleware-oriented remember-me authentication использует `CompensatingRememberMeStrategy`; raw `RememberMeStrategy` остаётся low-level primitive для callers, которые сами отвечают за публикацию и rollback результата. Direct `MagicLink\VerifyHandler` требует `ReplacingPayloadStorage`, чтобы queued credential прежнего principal не мог перезаписать новую session.

Полные breaking changes описаны в `MIGRATION-v2.md`, release invariants — в `QUALITY-GATES.md`.
