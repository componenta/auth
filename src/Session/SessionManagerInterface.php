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

    /** Returns true only for a currently authenticatable session credential. */
    public function exists(
        #[\SensitiveParameter]
        string $sessionId,
    ): bool;

    /** Returns only a currently authenticatable, non-replaced session. */
    public function find(
        #[\SensitiveParameter]
        string $sessionId,
    ): ?SessionInterface;

    public function all(UuidInterface $subjectId): SessionCollectionInterface;

    /**
     * Extends idle expiry when a write is due. Implementations must apply an
     * atomic last-active predicate in addition to any caller-side check.
     */
    public function touch(
        #[\SensitiveParameter]
        string $sessionId,
        ?\DateTimeImmutable $lastActiveAt = null,
    ): void;

    /**
     * Terminates the supplied credential lineages. A replacement created by a
     * concurrent regeneration must not remain authenticatable after this call.
     *
     * @param string|iterable<string>|SessionCollectionInterface $sessionId
     */
    public function terminate(
        #[\SensitiveParameter]
        string|iterable|SessionCollectionInterface $sessionId,
    ): void;

    public function terminateAll(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        ?string $exceptSessionId = null,
    ): void;

    /**
     * Rotates one active credential. A concurrent loser must fail instead of
     * receiving the winning successor ID.
     */
    public function regenerate(
        #[\SensitiveParameter]
        string $sessionId,
    ): SessionInterface;

    /** Removes at most $limit expired sessions and returns affected rows. */
    public function cleanup(int $limit = 1000): int;
}
