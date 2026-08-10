<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

interface SessionInterface
{
    public string $id { get; }
    public int|string $userId { get; }
    public \DateTimeImmutable $expiresAt { get; }
    public \DateTimeImmutable $absoluteExpiresAt { get; }
    public \DateTimeImmutable $regenerateAt { get; }
    public ?string $replacedBy { get; }
    public \DateTimeImmutable $createdAt { get; }
    public \DateTimeImmutable $lastActiveAt { get; }

    /** @var array<string, mixed> */
    public array $attributes { get; }

    public function hasAttribute(string $name): bool;

    public function getAttribute(string $name, mixed $default = null): mixed;
}
