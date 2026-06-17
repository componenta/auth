<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Manages user sessions.
 */
interface SessionManagerInterface
{
    /**
     * Creates a new session.
     *
     * @param array<string, mixed> $attributes Session metadata
     */
    public function create(int|string $userId, array $attributes = []): SessionInterface;

    /**
     * Checks if session exists.
     */
    public function exists(string $sessionId): bool;

    /**
     * Returns session by ID.
     */
    public function find(string $sessionId): ?SessionInterface;

    /**
     * Returns all active sessions for the user.
     */
    public function all(int|string $userId): SessionCollectionInterface;

    /**
     * Updates last activity timestamp.
     */
    public function touch(string $sessionId): void;

    /**
     * Terminates session(s).
     *
     * @param string|iterable<string>|SessionCollectionInterface $sessionId
     */
    public function terminate(string|iterable|SessionCollectionInterface $sessionId): void;

    /**
     * Terminates all sessions for the user.
     *
     * If $exceptSessionId is provided, that session is preserved.
     */
    public function terminateAll(int|string $userId, ?string $exceptSessionId = null): void;

    /**
     * Regenerates the session ID (canary).
     *
     * Creates a new session with a new ID, copying data from the old one.
     * The old session is marked as replaced and remains valid during
     * the grace period to handle concurrent requests.
     *
     * The absolute timeout is preserved from the original session.
     */
    public function regenerate(string $sessionId): SessionInterface;

    /**
     * Removes expired sessions (garbage collection).
     */
    public function cleanup(): void;
}