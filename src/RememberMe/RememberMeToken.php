<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

final readonly class RememberMeToken
{
    public function __construct(
        public int $id,
        public UuidInterface $subjectId,
        public ?string $sessionId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $createdAt,
    ) {
        if ($this->id < 1) {
            throw new \InvalidArgumentException(
                'Remember-me token ID must be positive.',
            );
        }

        if (
            $this->sessionId !== null
            && (
                $this->sessionId === ''
                || strlen($this->sessionId) > 512
                || preg_match('/[\x00-\x1F\x7F]/', $this->sessionId) === 1
            )
        ) {
            throw new \InvalidArgumentException(
                'Remember-me session ID is invalid.',
            );
        }

        if ($this->expiresAt <= $this->createdAt) {
            throw new \InvalidArgumentException(
                'Remember-me expiry must follow creation.',
            );
        }
    }
}
