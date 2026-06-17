<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * Generates cryptographically secure opaque token identifiers.
 *
 * Used for both refresh token IDs and family IDs.
 */
final readonly class RefreshTokenGenerator
{
    /**
     * @param int $length Number of random bytes (output is 2x hex characters)
     */
    public function __construct(
        private int $length = 32,
    ) {}

    public function generate(): string
    {
        return bin2hex(random_bytes($this->length));
    }
}
