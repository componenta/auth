<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

/**
 * Manages remember-me tokens for persistent authentication.
 *
 * Tokens are one-time use: validated, then rotated on each auto-login.
 * Plain tokens are stored in cookies; hashed tokens are stored in the database.
 */
interface RememberMeTokenManagerInterface
{
    /**
     * Creates a new remember-me token.
     *
     * Generates a random token, stores its hash in the database.
     *
     * @return string Plain token (for cookie)
     */
    public function create(int|string $userId, ?string $sessionId = null): string;

    /**
     * Atomically validates and consumes a remember-me token.
     *
     * Hashes the plain token, locks the row, checks expiration,
     * and deletes the token within a single transaction.
     * Prevents TOCTOU race conditions between validation and rotation.
     *
     * @return RememberMeToken|null Token data if valid, null otherwise
     */
    public function consume(string $plainToken): ?RememberMeToken;

    /**
     * Revokes a specific token.
     */
    public function revoke(string $plainToken): void;

    /**
     * Revokes the token linked to a specific session.
     */
    public function revokeForSession(string $sessionId): void;

    /**
     * Revokes all tokens for a user.
     *
     * @param string|null $exceptSessionId If set, keeps the token linked to this session.
     */
    public function revokeAllForUser(int|string $userId, ?string $exceptSessionId = null): void;

    /**
     * Updates the session ID for the token linked to the given session.
     *
     * Used during session regeneration to keep the token pointing
     * to the current (leaf) session.
     */
    public function updateSessionId(string $oldSessionId, string $newSessionId): void;

    /**
     * Removes expired tokens (garbage collection).
     */
    public function cleanup(): void;
}
