<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * JWT claims data transfer object.
 *
 * Represents the standard JWT claims used for
 * signing and verification.
 */
final readonly class Claims
{
    /**
     * @param string $subject User identifier (sub claim)
     * @param int $issuedAt Token creation timestamp (iat claim)
     * @param int $expiresAt Token expiration timestamp (exp claim)
     * @param string $issuer Token issuer (iss claim)
     * @param string $audience Token audience (aud claim)
     * @param int|null $notBefore Token activation timestamp (nbf claim), null if absent
     * @param array<string, mixed> $custom Additional custom claims
     */
    public function __construct(
        public string $subject,
        public int $issuedAt,
        public int $expiresAt,
        public string $issuer = '',
        public string $audience = '',
        public ?int $notBefore = null,
        public array $custom = [],
    ) {}
}
