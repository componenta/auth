<?php

declare(strict_types=1);

namespace Componenta\Auth;

final readonly class Context implements ContextInterface
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        public array $attributes = [],
    ) {}

    #[\Override]
    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->attributes)
            ? $this->attributes[$key]
            : $default;
    }

    #[\Override]
    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }

    #[\Override]
    public function withAttribute(string $key, mixed $value): static
    {
        return new self([...$this->attributes, $key => $value]);
    }

    #[\Override]
    public function withAttributes(array $attributes): static
    {
        return new self([...$this->attributes, ...$attributes]);
    }
}
