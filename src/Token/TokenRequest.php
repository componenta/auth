<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequest
{
    /** @param array<string, string> $context */
    public function __construct(
        public string $identity,
        public ?string $destination = null,
        public array $context = [],
    ) {}
}
