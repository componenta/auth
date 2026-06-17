<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\IdentityInterface;

/**
 * Provides user lookup for token-based flows (magic link, password reset, etc.).
 *
 * Two methods for the two steps of a token flow:
 * - Request step: find user by identity (email, phone)
 * - Verify/consume step: find user by ID (from token's embedded userId)
 */
interface UserProviderInterface
{
    /**
     * Finds a user by their identity (email or phone number).
     *
     * Used during the request step to resolve identity to userId
     * before generating a token.
     */
    public function findByIdentity(string $identity): ?IdentityInterface;

    /**
     * Finds a user by their unique identifier.
     *
     * Used during the verify/consume step to load the user
     * from the token's embedded userId.
     */
    public function findById(string $userId): ?IdentityInterface;
}
