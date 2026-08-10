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
    private const int MAX_SUBJECT_ID_LENGTH = 512;

    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenGenerator $generator,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function issue(string $userId): RefreshToken
    {
        self::assertSubjectId($userId);
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

    public function revokeAllForUser(string $userId): void
    {
        self::assertSubjectId($userId);
        $this->store->revokeAllForUser($userId, $this->now());
    }

    private function validatedSuccessor(
        RefreshTokenRotationResult $result,
        string $successorId,
        int $successorExpiresAt,
    ): RefreshToken {
        $token = $result->token
            ?? throw new \LogicException('A rotated result must contain the successor token.');

        if (
            $token->id !== $successorId
            || $token->expiresAt !== $successorExpiresAt
            || $token->revoked
            || !self::validTokenId($token->familyId)
            || $token->userId === ''
        ) {
            throw new \LogicException('Refresh token store returned an invalid successor.');
        }

        return $token;
    }

    private static function validTokenId(string $id): bool
    {
        return preg_match('/\A[a-f0-9]{64,128}\z/D', $id) === 1
            && strlen($id) % 2 === 0;
    }

    private static function assertSubjectId(string $userId): void
    {
        if ($userId === '' || strlen($userId) > self::MAX_SUBJECT_ID_LENGTH) {
            throw new \InvalidArgumentException('Refresh token subject ID is invalid.');
        }
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
