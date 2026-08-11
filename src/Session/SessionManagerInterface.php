<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Identity\UuidInterface;

interface SessionManagerInterface
{
    /** @param array<string, mixed> $attributes */
    public function create(
        UuidInterface $subjectId,
        array $attributes = [],
    ): SessionInterface;

    public function exists(string $sessionId): bool;

    public function find(string $sessionId): ?SessionInterface;

    public function all(UuidInterface $subjectId): SessionCollectionInterface;

    /**
     * Extends idle expiry when a write is due. Implementations must apply an
     * atomic last-active predicate in addition to any caller-side check.
     */
    public function touch(
        string $sessionId,
        ?\DateTimeImmutable $lastActiveAt = null,
    ): void;

    /** @param string|iterable<string>|SessionCollectionInterface $sessionId */
    public function terminate(
        string|iterable|SessionCollectionInterface $sessionId,
    ): void;

    public function terminateAll(
        UuidInterface $subjectId,
        ?string $exceptSessionId = null,
    ): void;

    public function regenerate(string $sessionId): SessionInterface;

    /** Removes at most $limit expired sessions and returns affected rows. */
    public function cleanup(int $limit = 1000): int;
}
