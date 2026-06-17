<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Session;

use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Identity\IdentityInterface;

/**
 * Provides user lookup for session-based authentication.
 *
 * Used by SessionStrategy to resolve user from session's userId.
 */
interface UserProviderInterface
{
    /**
     * Finds a user by their unique identifier.
     *
     * @param int|string $userId The user ID stored in the session
     * @return (IdentityInterface&SessionAwareInterface)|null The user, or null if not found
     */
    public function findById(int|string $userId): (IdentityInterface&SessionAwareInterface)|null;
}
