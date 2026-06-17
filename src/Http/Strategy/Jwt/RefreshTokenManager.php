<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\Denied\RefreshTokenExpired;
use Componenta\Auth\Http\Strategy\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

/**
 * Manages refresh token lifecycle: issue, rotate, revoke.
 *
 * Implements token rotation with reuse detection:
 * - Each authentication creates a new token family
 * - Rotation issues a new token in the same family
 * - If a revoked token is reused, the entire family is revoked
 *   (indicates potential token theft)
 */
final readonly class RefreshTokenManager
{
    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenGenerator $generator,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    /**
     * Issues a new refresh token with a new family.
     *
     * Called after successful authentication to create
     * the initial refresh token.
     */
    public function issue(string $userId): RefreshToken
    {
        $token = new RefreshToken(
            id: $this->generator->generate(),
            userId: $userId,
            familyId: $this->generator->generate(),
            expiresAt: $this->now() + $this->config->refreshTtl,
        );

        $this->store->store($token);

        return $token;
    }

    /**
     * Rotates a refresh token: revokes the old one, issues a new one.
     *
     * Reuse detection is enforced atomically: `revokeIfActive()` is a
     * compare-and-swap that succeeds only if the token is still active.
     * Two concurrent rotations of the same token can no longer both
     * succeed - the loser treats this as theft and revokes the family.
     *
     * @return RefreshToken|DeniedReasonInterface New token on success, denial on failure
     */
    public function rotate(string $tokenId): RefreshToken|DeniedReasonInterface
    {
        $existing = $this->store->find($tokenId);

        if ($existing === null) {
            return new InvalidRefreshToken();
        }

        $now = $this->now();

        // Already revoked on read - classic reuse of a stolen token.
        if ($existing->isRevoked()) {
            $this->store->revokeFamily($existing->familyId, $now);

            return new TokenFamilyCompromised();
        }

        if ($existing->isExpired($now)) {
            return new RefreshTokenExpired();
        }

        // Atomic claim. If a concurrent rotation already revoked this token
        // between our find() and here, revokeIfActive() returns false and
        // we treat it as reuse - revoke the whole family.
        if (!$this->store->revokeIfActive($tokenId, $now)) {
            $this->store->revokeFamily($existing->familyId, $now);

            return new TokenFamilyCompromised();
        }

        $newToken = new RefreshToken(
            id: $this->generator->generate(),
            userId: $existing->userId,
            familyId: $existing->familyId,
            expiresAt: $now + $this->config->refreshTtl,
        );

        $this->store->store($newToken);

        return $newToken;
    }

    /**
     * Revokes a single refresh token (e.g., on logout).
     */
    public function revoke(string $tokenId): void
    {
        $this->store->revoke($tokenId, $this->now());
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
