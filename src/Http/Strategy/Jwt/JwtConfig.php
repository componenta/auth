<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * Configuration for JWT authentication.
 */
final readonly class JwtConfig
{
    /**
     * @param int $accessTtl Access token lifetime in seconds
     * @param int $refreshTtl Refresh token lifetime in seconds
     * @param string $issuer JWT issuer claim (iss)
     * @param string $audience JWT audience claim (aud)
     */
    public function __construct(
        public int $accessTtl = 900,
        public int $refreshTtl = 604800,
        public string $issuer = '',
        public string $audience = '',
    ) {
        if ($this->accessTtl < 1) {
            throw new \InvalidArgumentException('Access TTL must be positive');
        }

        if ($this->refreshTtl < 1) {
            throw new \InvalidArgumentException('Refresh TTL must be positive');
        }
    }
}
