<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/**
 * Represents a one-time token stored in the database.
 *
 * Used for magic links, password resets, and similar flows.
 */
final readonly class Token
{
    public function __construct(
        public int $id,
        public string $userId,
        public \DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $usedAt,
        public \DateTimeImmutable $createdAt,
    ) {}
}
