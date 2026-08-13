<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\Denied\RefreshTokenExpired;
use Componenta\Auth\Http\Strategy\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Clock\Clock;
use Componenta\Identity\UuidInterface;
use Psr\Clock\ClockInterface;

final readonly class RefreshTokenManager
{
    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenGenerator $generator,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function issue(UuidInterface $subjectId): RefreshToken
    {
        $token = new RefreshToken(
            id: $this->generator->generate(),
            subjectId: $subjectId,
            familyId: $this->generator->generate(),
            expiresAt: $this->now() + $this->config->refreshTtl,
        );
        $this->store->storeInitial($token);

        return $token;
    }

    /**
     * Non-authoritative preflight used to complete fallible provider/signing
     * work before rotating the presented bearer. rotate() remains the final
     * serialized authorization decision.
     */
    public function findActiveSubject(string $tokenId): ?UuidInterface
    {
        if (!self::validTokenId($tokenId)) {
            return null;
        }

        return $this->store->findActiveSubject($tokenId, $this->now());
    }

    public function rotate(string $tokenId): RefreshToken|DeniedReasonInterface
    {
        if (!self::validTokenId($tokenId)) {
            return new InvalidRefreshToken();
        }

        $now = $this->now();
        $successorId = $this->generator->generate();
        $successorExpiresAt = $now + $this->config->refreshTtl;
        $result = $this->store->rotateAtomically(
            presentedTokenId: $tokenId,
            successorTokenId: $successorId,
            successorExpiresAt: $successorExpiresAt,
            now: $now,
        );

        return match ($result->status) {
            RefreshTokenRotationStatus::Rotated => $this->validatedSuccessor(
                $result,
                $successorId,
                $successorExpiresAt,
            ),
            RefreshTokenRotationStatus::Invalid => new InvalidRefreshToken(),
            RefreshTokenRotationStatus::Expired => new RefreshTokenExpired(),
            RefreshTokenRotationStatus::Reused => new TokenFamilyCompromised(),
        };
    }

    public function revoke(string $tokenId): void
    {
        if (self::validTokenId($tokenId)) {
            $this->store->revoke($tokenId, $this->now());
        }
    }

    public function revokeAllForSubject(UuidInterface $subjectId): void
    {
        $this->store->revokeAllForSubject($subjectId, $this->now());
    }

    private function validatedSuccessor(
        RefreshTokenRotationResult $result,
        string $successorId,
        int $successorExpiresAt,
    ): RefreshToken {
        $token = $result->token
            ?? throw new \LogicException(
                'A rotated result must contain the successor token.',
            );

        if (
            $token->id !== $successorId
            || $token->expiresAt !== $successorExpiresAt
            || $token->revoked
            || !self::validTokenId($token->familyId)
        ) {
            throw new \LogicException(
                'Refresh token store returned an invalid successor.',
            );
        }

        return $token;
    }

    private static function validTokenId(string $id): bool
    {
        return preg_match('/\A[a-f0-9]{64,128}\z/D', $id) === 1
            && strlen($id) % 2 === 0;
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
