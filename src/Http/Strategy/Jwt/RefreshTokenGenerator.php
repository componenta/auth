<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

final readonly class RefreshTokenGenerator
{
    public function __construct(
        private int $length = 32,
    ) {
        if ($this->length < 32 || $this->length > 64) {
            throw new \InvalidArgumentException('Refresh token entropy must be between 32 and 64 bytes.');
        }
    }

    public function generate(): string
    {
        return bin2hex(random_bytes($this->length));
    }
}
