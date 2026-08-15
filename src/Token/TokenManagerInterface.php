<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\UuidInterface;

interface TokenManagerInterface
{
    /**
     * Atomically replaces the subject's active challenge and returns plaintext.
     * Persistence must enforce at most one active row per subject and purpose.
     */
    public function replaceForSubject(UuidInterface $subjectId): string;

    public function find(
        #[\SensitiveParameter]
        string $plainToken,
    ): ?Token;

    public function consume(
        #[\SensitiveParameter]
        string $plainToken,
    ): bool;

    /** Removes at most $limit expired or consumed tokens. */
    public function cleanup(int $limit = 1000): int;
}
