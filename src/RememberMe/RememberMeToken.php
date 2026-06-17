<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

/**
 * Represents a stored remember-me token.
 */
final readonly class RememberMeToken
{
    public function __construct(
        public int $id,
        public int|string $userId,
        public ?string $sessionId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $createdAt,
    ) {}
}
