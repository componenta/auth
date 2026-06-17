<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * Represents an opaque refresh token.
 *
 * Refresh tokens are stateful - stored in a persistent store
 * (database, Redis) and tracked for rotation and revocation.
 *
 * The familyId groups related tokens from the same initial
 * authentication, enabling reuse detection: if a revoked token
 * is presented, the entire family is revoked.
 */
final readonly class RefreshToken
{
    /**
     * @param string $id Opaque token identifier (sent to client)
     * @param string $userId Owner of the token
     * @param string $familyId Rotation chain identifier
     * @param int $expiresAt Expiration timestamp
     * @param int|null $revokedAt Revocation timestamp, null if active
     */
    public function __construct(
        public string $id,
        public string $userId,
        public string $familyId,
        public int $expiresAt,
        public ?int $revokedAt = null,
    ) {}

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }
}
