<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

/**
 * Owns the complete account-recovery security transition.
 *
 * The service validates and locks the reset token before performing expensive
 * password hashing. Success means the token is consumed, the password is
 * changed, and every pre-reset long-lived credential for the subject is
 * durably or logically invalid. Multi-store implementations must use a
 * credential version plus transactional outbox/idempotent retry rather than
 * reporting partial success.
 */
interface PasswordResetServiceInterface
{
    public function reset(
        #[\SensitiveParameter]
        string $plainToken,
        #[\SensitiveParameter]
        string $newPassword,
    ): PasswordResetResult;
}
