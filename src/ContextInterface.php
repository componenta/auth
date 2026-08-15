<?php

declare(strict_types=1);

namespace Componenta\Auth;

interface ContextInterface
{
    public const string EXTRACTOR = '__extractor';

    /** @var array<string, mixed> */
    public array $attributes { get; }

    public function getAttribute(string $key, mixed $default = null): mixed;

    public function hasAttribute(string $key): bool;

    public function withAttribute(
        string $key,
        #[\SensitiveParameter]
        mixed $value,
    ): static;

    /** @param array<string, mixed> $attributes */
    public function withAttributes(
        #[\SensitiveParameter]
        array $attributes,
    ): static;
}
