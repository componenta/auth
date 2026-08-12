<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

interface RememberMeTokenManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        string $sessionId,
    ): string;

    /** Atomically invalidates the presented bearer and returns its successor. */
    public function rotate(string $plainToken): ?RememberMeRotation;

    /**
     * Binds a rotated grant to a new session. False means the grant was revoked
     * or changed concurrently and the caller must not issue the new session.
     */
    public function bindRotation(
        RememberMeRotation $rotation,
        string $newSessionId,
    ): bool;

    public function revoke(string $plainToken): void;

    public function revokeForSession(string $sessionId): void;

    /** @param iterable<string> $sessionIds */
    public function revokeForSessions(iterable $sessionIds): void;

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?string $exceptSessionId = null,
    ): void;

    public function updateSessionId(
        string $oldSessionId,
        string $newSessionId,
    ): void;

    /** Removes at most $limit expired grants and returns affected rows. */
    public function cleanup(int $limit = 1000): int;
}
