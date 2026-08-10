<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class RefreshTokenManagerTest extends TestCase
{
    public function testRotationIsOneStoreLevelOperationAndMapsReuseToCompromise(): void
    {
        $store = new RefreshStoreFixture(RefreshTokenRotationResult::reused());
        $manager = new RefreshTokenManager(
            $store,
            new RefreshTokenGenerator(8),
            new JwtConfig(refreshTtl: 60),
            new FixedClockFixture(),
        );

        $result = $manager->rotate('presented');

        self::assertInstanceOf(TokenFamilyCompromised::class, $result);
        self::assertSame('presented', $store->presented);
        self::assertSame(1000, $store->now);
        self::assertNotSame('', $store->successor);
    }

    public function testSuccessfulAtomicRotationReturnsStoreAuthoritativeToken(): void
    {
        $token = new RefreshToken('next', 'user', 'family', 1060);
        $store = new RefreshStoreFixture(RefreshTokenRotationResult::rotated($token));
        $manager = new RefreshTokenManager(
            $store,
            new RefreshTokenGenerator(8),
            new JwtConfig(refreshTtl: 60),
            new FixedClockFixture(),
        );

        self::assertSame($token, $manager->rotate('old'));
    }
}

final class RefreshStoreFixture implements RefreshTokenStoreInterface
{
    public ?string $presented = null;
    public ?string $successor = null;
    public ?int $now = null;

    public function __construct(private RefreshTokenRotationResult $result) {}
    public function storeInitial(RefreshToken $token): void {}

    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        $this->presented = $presentedTokenId;
        $this->successor = $successorTokenId;
        $this->now = $now;
        return $this->result;
    }

    public function revoke(string $tokenId, int $revokedAt): void {}
    public function revokeAllForUser(int|string $userId, int $revokedAt): void {}
}

final readonly class FixedClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
