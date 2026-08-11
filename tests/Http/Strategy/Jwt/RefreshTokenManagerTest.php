<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class RefreshTokenManagerTest extends TestCase
{
    private const string TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string FAMILY = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    public function testRotationIsOneStoreOperationAndMapsReuseToCompromise(): void
    {
        $store = new RefreshStoreFixture(static fn(): RefreshTokenRotationResult => RefreshTokenRotationResult::reused());
        $manager = $this->manager($store);

        $result = $manager->rotate(self::TOKEN);

        self::assertInstanceOf(TokenFamilyCompromised::class, $result);
        self::assertSame(self::TOKEN, $store->presented);
        self::assertSame(1000, $store->now);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $store->successor ?? '');
    }

    public function testSuccessfulRotationUsesTheRequestedSuccessor(): void
    {
        $store = new RefreshStoreFixture(
            static fn(string $successor, int $expiresAt): RefreshTokenRotationResult =>
                RefreshTokenRotationResult::rotated(new RefreshToken(
                    $successor,
                    Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                    self::FAMILY,
                    $expiresAt,
                )),
        );
        $result = $this->manager($store)->rotate(self::TOKEN);

        self::assertInstanceOf(RefreshToken::class, $result);
        self::assertSame($store->successor, $result->id);
    }

    public function testMalformedTokenDoesNotReachStore(): void
    {
        $store = new RefreshStoreFixture(static fn(): never => throw new \LogicException('must not run'));
        $result = $this->manager($store)->rotate('invalid');

        self::assertInstanceOf(InvalidRefreshToken::class, $result);
        self::assertNull($store->presented);
    }

    private function manager(RefreshStoreFixture $store): RefreshTokenManager
    {
        return new RefreshTokenManager(
            $store,
            new RefreshTokenGenerator(),
            new JwtConfig('https://issuer.example', 'componenta-api', refreshTtl: 60),
            new FixedClockFixture(),
        );
    }
}

final class RefreshStoreFixture implements RefreshTokenStoreInterface
{
    public ?string $presented = null;
    public ?string $successor = null;
    public ?int $now = null;

    /** @param \Closure(string, int): RefreshTokenRotationResult $rotation */
    public function __construct(private \Closure $rotation) {}
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

        return ($this->rotation)($successorTokenId, $successorExpiresAt);
    }

    public function revoke(string $tokenId, int $revokedAt): void {}
    public function revokeAllForSubject(UuidInterface $subjectId, int $revokedAt): void {}
}

final readonly class FixedClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
