<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Identity\UuidInterface;

final readonly class Session implements SessionInterface
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        public string $id,
        public UuidInterface $subjectId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $absoluteExpiresAt,
        public \DateTimeImmutable $regenerateAt,
        public ?string $replacedBy,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $lastActiveAt,
        public array $attributes = [],
    ) {
        if (
            $this->id === ''
            || strlen($this->id) > 512
            || preg_match('/[\x00-\x1F\x7F]/', $this->id) === 1
        ) {
            throw new \InvalidArgumentException('Session ID is invalid.');
        }

        if (
            $this->replacedBy !== null
            && (
                $this->replacedBy === ''
                || strlen($this->replacedBy) > 512
                || preg_match('/[\x00-\x1F\x7F]/', $this->replacedBy) === 1
            )
        ) {
            throw new \InvalidArgumentException(
                'Replacement session ID is invalid.',
            );
        }

        if ($this->replacedBy === $this->id) {
            throw new \InvalidArgumentException(
                'A session cannot be replaced by itself.',
            );
        }

        if (
            $this->expiresAt <= $this->createdAt
            || $this->absoluteExpiresAt <= $this->createdAt
        ) {
            throw new \InvalidArgumentException(
                'Session expiry bounds are invalid.',
            );
        }

        if (
            $this->regenerateAt < $this->createdAt
        ) {
            throw new \InvalidArgumentException(
                'Session regeneration time is invalid.',
            );
        }

        if ($this->lastActiveAt < $this->createdAt) {
            throw new \InvalidArgumentException(
                'Session last-active time cannot precede creation.',
            );
        }
    }

    #[\Override]
    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }

    #[\Override]
    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->attributes)
            ? $this->attributes[$name]
            : $default;
    }
}
