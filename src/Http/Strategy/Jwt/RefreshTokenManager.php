<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\Denied\RefreshTokenExpired;
use Componenta\Auth\Http\Strategy\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

final readonly class RefreshTokenManager
{
    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenGenerator $generator,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function issue(string $userId): RefreshToken
    {
        $token = new RefreshToken(
            id: $this->generator->generate(),
            userId: $userId,
            familyId: $this->generator->generate(),
            expiresAt: $this->now() + $this->config->refreshTtl,
        );

        $this->store->storeInitial($token);

        return $token;
    }

    public function rotate(string $tokenId): RefreshToken|DeniedReasonInterface
    {
        $now = $this->now();
        $result = $this->store->rotateAtomically(
            presentedTokenId: $tokenId,
            successorTokenId: $this->generator->generate(),
            successorExpiresAt: $now + $this->config->refreshTtl,
            now: $now,
        );

        return match ($result->status) {
            RefreshTokenRotationStatus::Rotated => $result->token
                ?? throw new \LogicException('A rotated refresh result must contain the successor token.'),
            RefreshTokenRotationStatus::Invalid => new InvalidRefreshToken(),
            RefreshTokenRotationStatus::Expired => new RefreshTokenExpired(),
            RefreshTokenRotationStatus::Reused => new TokenFamilyCompromised(),
        };
    }

    public function revoke(string $tokenId): void
    {
        $this->store->revoke($tokenId, $this->now());
    }

    public function revokeAllForUser(string $userId): void
    {
        $this->store->revokeAllForUser($userId, $this->now());
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
