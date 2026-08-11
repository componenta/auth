<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

interface RememberMeTokenManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        ?string $sessionId = null,
    ): string;

    public function consume(string $plainToken): ?RememberMeToken;

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

    /** Removes at most $limit expired tokens and returns affected rows. */
    public function cleanup(int $limit = 1000): int;
}
