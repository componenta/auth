<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

/**
 * Owns the account-recovery security transition.
 *
 * Success means the reset token was consumed, the password was changed, and
 * every pre-reset long-lived credential for the subject (sessions,
 * remember-me tokens and refresh grants) is durably or logically invalid.
 * Implementations using multiple stores must use a credential version and a
 * transactional outbox/idempotent retry instead of reporting partial success.
 */
interface PasswordResetServiceInterface
{
    public function reset(string $plainToken, string $passwordHash): PasswordResetResult;
}
