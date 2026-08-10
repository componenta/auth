<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class Session implements SessionInterface
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        public string $id,
        public int|string $userId,
        public \DateTimeImmutable $expiresAt,
        public \DateTimeImmutable $absoluteExpiresAt,
        public \DateTimeImmutable $regenerateAt,
        public ?string $replacedBy,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $lastActiveAt,
        public array $attributes = [],
    ) {}

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
