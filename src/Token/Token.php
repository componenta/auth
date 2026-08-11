<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\UuidInterface;

final readonly class Token
{
    public function __construct(
        public int $id,
        public UuidInterface $subjectId,
        public \DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $usedAt,
        public \DateTimeImmutable $createdAt,
    ) {
        if ($this->id < 1) {
            throw new \InvalidArgumentException('Token ID must be positive.');
        }

        if ($this->expiresAt <= $this->createdAt) {
            throw new \InvalidArgumentException(
                'Token expiry must follow creation.',
            );
        }

        if ($this->usedAt !== null && $this->usedAt < $this->createdAt) {
            throw new \InvalidArgumentException(
                'Token use time cannot precede creation.',
            );
        }
    }
}
