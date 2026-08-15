<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

interface RememberMeTokenManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $sessionId,
    ): string;

    /**
     * Atomically rotates a current bearer. A superseded bearer revokes its
     * grant and returns the affected session lineage as a compromise signal.
     */
    public function rotate(
        #[\SensitiveParameter]
        string $plainToken,
    ): RememberMeRotation|RememberMeCompromise|null;

    /**
     * Binds a rotated grant to a new session. False means the grant was revoked
     * or changed concurrently and the caller must not issue the new session.
     */
    public function bindRotation(
        #[\SensitiveParameter]
        RememberMeRotation $rotation,
        #[\SensitiveParameter]
        string $newSessionId,
    ): bool;

    public function revoke(
        #[\SensitiveParameter]
        string $plainToken,
    ): void;

    public function revokeForSession(
        #[\SensitiveParameter]
        string $sessionId,
    ): void;

    /** @param iterable<string> $sessionIds */
    public function revokeForSessions(
        #[\SensitiveParameter]
        iterable $sessionIds,
    ): void;

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        ?string $exceptSessionId = null,
    ): void;

    public function updateSessionId(
        #[\SensitiveParameter]
        string $oldSessionId,
        #[\SensitiveParameter]
        string $newSessionId,
    ): void;

    /** Removes at most $limit expired grants and returns affected rows. */
    public function cleanup(int $limit = 1000): int;
}