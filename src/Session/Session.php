<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Default implementation of SessionInterface.
 */
final readonly class Session implements SessionInterface
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        public string $id,
        public int|string $userId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $absoluteExpiresAt,
        public \DateTimeImmutable $regenerateAt,
        public ?string $replacedBy,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $lastActiveAt,
        private(set) array $attributes = [],
    ) {}

    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }

    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }
}