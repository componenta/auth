<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\Http\Strategy\Jwt\Claims;
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

final class JwtStrategyTest extends TestCase
{
    public function testExactIssuerAudienceAndTypeAreRequired(): void
    {
        $identity = new JwtIdentityFixture();
        $strategy = new JwtStrategy(
            new JwtSignerFixture(new Claims(
                subject: $identity->uuid->toString(),
                issuedAt: 900,
                expiresAt: 1100,
                issuer: 'https://wrong.example',
                audience: 'componenta-api',
                type: 'at+jwt',
            )),
            new JwtProviderFixture($identity),
            new JwtConfig('https://issuer.example', 'componenta-api'),
            new JwtClockFixture(),
        );
        $result = $strategy->attempt(new BearerPayload('token'), new Context());

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
    }

    public function testValidProfileResolvesIdentity(): void
    {
        $identity = new JwtIdentityFixture();
        $strategy = new JwtStrategy(
            new JwtSignerFixture(new Claims(
                subject: $identity->uuid->toString(),
                issuedAt: 900,
                expiresAt: 1100,
                issuer: 'https://issuer.example',
                audience: 'componenta-api',
                type: 'at+jwt',
            )),
            new JwtProviderFixture($identity),
            new JwtConfig('https://issuer.example', 'componenta-api'),
            new JwtClockFixture(),
        );

        self::assertSame(
            $identity,
            $strategy->attempt(new BearerPayload('token'), new Context())->subject,
        );
    }

    public function testProviderCannotSubstituteDifferentIdentity(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $other = new class implements IdentityInterface {
            public UuidInterface $uuid {
                get => Uuid::fromString(
                    '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
                );
            }
        };
        $strategy = new JwtStrategy(
            new JwtSignerFixture(new Claims(
                subject: $subjectId->toString(),
                issuedAt: 900,
                expiresAt: 1100,
                issuer: 'https://issuer.example',
                audience: 'componenta-api',
                type: 'at+jwt',
            )),
            new JwtProviderFixture($other),
            new JwtConfig('https://issuer.example', 'componenta-api'),
            new JwtClockFixture(),
        );

        $result = $strategy->attempt(new BearerPayload('token'), new Context());

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
    }
}

final readonly class JwtSignerFixture implements SignerInterface
{
    public function __construct(private ?Claims $claims) {}
    public function sign(Claims $claims): string { return 'token'; }
    public function parse(string $token): ?Claims { return $this->claims; }
}

final readonly class JwtProviderFixture implements JwtUserProviderInterface
{
    public function __construct(private ?IdentityInterface $identity) {}
    public function findByUuid(UuidInterface $uuid): ?IdentityInterface { return $this->identity; }
}

final class JwtIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}

final readonly class JwtClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable { return new DateTimeImmutable('@1000'); }
}
