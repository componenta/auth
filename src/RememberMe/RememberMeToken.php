<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Identity\UuidInterface;

final readonly class RememberMeToken implements \JsonSerializable
{
    public function __construct(
        public int $id,
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
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

    /** @return array<string, int|string|null|bool> */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'subjectId' => $this->subjectId->toString(),
            'sessionId' => $this->sessionId === null ? null : '[REDACTED]',
            'expiresAt' => $this->expiresAt->getTimestamp(),
            'createdAt' => $this->createdAt->getTimestamp(),
        ];
    }

    /** @return array<string, int|string|null|bool> */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
