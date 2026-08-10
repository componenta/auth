<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/** Configuration of one explicit access-token validation profile. */
final readonly class JwtConfig
{
    public function __construct(
        public string $issuer,
        public string $audience,
        public string $type = 'at+jwt',
        public int $accessTtl = 900,
        public int $refreshTtl = 604800,
        public int $clockSkew = 30,
    ) {
        foreach (['issuer' => $this->issuer, 'audience' => $this->audience, 'type' => $this->type] as $name => $value) {
            if ($value === '' || strlen($value) > 2048 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
                throw new \InvalidArgumentException(sprintf('JWT %s must be a bounded non-empty string.', $name));
            }
        }

        if ($this->accessTtl < 1) {
            throw new \InvalidArgumentException('Access TTL must be positive.');
        }

        if ($this->refreshTtl < 1) {
            throw new \InvalidArgumentException('Refresh TTL must be positive.');
        }

        if ($this->clockSkew < 0 || $this->clockSkew > 300) {
            throw new \InvalidArgumentException('JWT clock skew must be between 0 and 300 seconds.');
        }
    }
}
