<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

interface RememberMeTokenManagerInterface
{
    public function create(int|string $userId, ?string $sessionId = null): string;

    public function consume(string $plainToken): ?RememberMeToken;

    public function revoke(string $plainToken): void;

    public function revokeForSession(string $sessionId): void;

    /** @param iterable<string> $sessionIds */
    public function revokeForSessions(iterable $sessionIds): void;

    public function revokeAllForUser(int|string $userId, ?string $exceptSessionId = null): void;

    public function updateSessionId(string $oldSessionId, string $newSessionId): void;

    public function cleanup(): void;
}
