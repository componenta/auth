<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/**
 * Manages one-time tokens (magic links, password resets, etc.).
 *
 * Tokens are generated as random bytes, stored as SHA-256 hashes.
 * The plain token is sent to the user; consuming is atomic.
 */
interface TokenManagerInterface
{
    /**
     * Generates a token for the given user.
     *
     * @return string Plain token (to send to the user)
     */
    public function generate(string $userId): string;

    /**
     * Finds a token by its plain value.
     *
     * Returns the token regardless of its state (used, expired).
     * The caller is responsible for checking the state.
     */
    public function find(string $plainToken): ?Token;

    /**
     * Atomically consumes a token (marks as used).
     *
     * Returns true if the token was successfully consumed, false if it was
     * already used, expired, or does not exist.
     */
    public function consume(string $plainToken): bool;

    /**
     * Revokes all tokens for a user.
     */
    public function revokeForUser(string $userId): void;

    /**
     * Removes expired and used tokens (garbage collection).
     */
    public function cleanup(): void;
}
