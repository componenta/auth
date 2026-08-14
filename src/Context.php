<?php

declare(strict_types=1);

namespace Componenta\Auth;

final readonly class Context implements ContextInterface, \JsonSerializable
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        #[\SensitiveParameter]
        public array $attributes = [],
    ) {}

    /** @return array{attributeKeys: list<string>} */
    public function __debugInfo(): array
    {
        return ['attributeKeys' => array_keys($this->attributes)];
    }

    /** @return array{attributeKeys: list<string>} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

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
    public function withAttribute(
        string $key,
        #[\SensitiveParameter]
        mixed $value,
    ): static {
        return new self([...$this->attributes, $key => $value]);
    }

    #[\Override]
    public function withAttributes(
        #[\SensitiveParameter]
        array $attributes,
    ): static {
        return new self([...$this->attributes, ...$attributes]);
    }
}
