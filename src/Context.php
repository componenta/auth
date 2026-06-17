<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Default implementation of ContextInterface.
 */
final readonly class Context implements ContextInterface
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        private array $attributes = [],
    ) {}

    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return $this->attributes[$key] ?? $default;
    }

    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function withAttribute(string $key, mixed $value): static
    {
        return new self([...$this->attributes, $key => $value]);
    }

    public function withAttributes(array $attributes): static
    {
        return new self([...$this->attributes, ...$attributes]);
    }
}
