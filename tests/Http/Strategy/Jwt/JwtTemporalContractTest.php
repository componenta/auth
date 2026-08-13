<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\Http\Strategy\Jwt\Claims;
use Componenta\Auth\Http\Strategy\Jwt\Denied\AccessTokenExpired;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidAccessToken;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\JwtStrategy;
use Componenta\Auth\Http\Strategy\Jwt\JwtUserProviderInterface;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class JwtTemporalContractTest extends TestCase
{
    public function testTokenExpiredAtClockSkewBoundaryIsRejectedAsExpired(): void
    {
        $result = $this->attempt(new Claims(
            subject: JwtTemporalIdentityFixture::UUID,
            issuedAt: 900,
            expiresAt: 970,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
        ));

        self::assertInstanceOf(AccessTokenExpired::class, $result->subject);
    }

    public function testTokenInsideExpiryClockSkewRemainsValid(): void
    {
        $identity = new JwtTemporalIdentityFixture();
        $result = $this->attempt(new Claims(
            subject: $identity->uuid->toString(),
            issuedAt: 900,
            expiresAt: 971,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
        ), identity: $identity);

        self::assertSame($identity, $result->subject);
    }

    public function testIssuedAtBeyondClockSkewIsRejected(): void
    {
        $result = $this->attempt(new Claims(
            subject: JwtTemporalIdentityFixture::UUID,
            issuedAt: 1031,
            expiresAt: 1100,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
        ));

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
    }

    public function testNotBeforeBeyondClockSkewIsRejected(): void
    {
        $result = $this->attempt(new Claims(
            subject: JwtTemporalIdentityFixture::UUID,
            issuedAt: 900,
            expiresAt: 1100,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
            notBefore: 1031,
        ));

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
    }

    public function testTokenLifetimeCannotExceedConfiguredAccessTtl(): void
    {
        $result = $this->attempt(new Claims(
            subject: JwtTemporalIdentityFixture::UUID,
            issuedAt: 900,
            expiresAt: 1001,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
        ), accessTtl: 100);

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
    }

    private function attempt(
        Claims $claims,
        ?IdentityInterface $identity = null,
        int $accessTtl = 900,
    ): \Componenta\Auth\AuthenticationResult {
        $strategy = new JwtStrategy(
            new JwtTemporalSignerFixture($claims),
            new JwtTemporalProviderFixture($identity ?? new JwtTemporalIdentityFixture()),
            new JwtConfig(
                'https://issuer.example',
                'componenta-api',
                accessTtl: $accessTtl,
                clockSkew: 30,
            ),
            new JwtTemporalClockFixture(),
        );

        return $strategy->attempt(new BearerPayload('token'), new Context());
    }
}

final readonly class JwtTemporalSignerFixture implements SignerInterface
{
    public function __construct(private Claims $claims) {}

    public function sign(Claims $claims): string
    {
        return 'token';
    }

    public function parse(string $token): Claims
    {
        return $this->claims;
    }
}

final readonly class JwtTemporalProviderFixture implements JwtUserProviderInterface
{
    public function __construct(private ?IdentityInterface $identity) {}

    public function findByUuid(UuidInterface $uuid): ?IdentityInterface
    {
        return $this->identity;
    }
}

final class JwtTemporalIdentityFixture implements IdentityInterface
{
    public const string UUID = '018f6d5d-3f7a-7a9b-8c2f-123456789abc';

    public UuidInterface $uuid {
        get => Uuid::fromString(self::UUID);
    }
}

final readonly class JwtTemporalClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
