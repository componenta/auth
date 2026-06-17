<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\IdentityInterface;

/**
 * Provides user lookup for JWT authentication.
 *
 * Used by JwtStrategy to resolve user from access token subject,
 * and by RefreshHandler to resolve user during token rotation.
 */
interface JwtUserProviderInterface
{
    /**
     * Finds a user by their unique identifier.
     *
     * @param string $userId The user ID from the JWT subject claim
     * @return IdentityInterface|null The user, or null if not found
     */
    public function findById(string $userId): ?IdentityInterface;
}
