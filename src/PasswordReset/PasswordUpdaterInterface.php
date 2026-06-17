<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

/**
 * Updates a user's password hash.
 *
 * Decouples the reset handler from the ORM/entity layer.
 */
interface PasswordUpdaterInterface
{
    public function updatePassword(string $userId, string $passwordHash): void;
}
