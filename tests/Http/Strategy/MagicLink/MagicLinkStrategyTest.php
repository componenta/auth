<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Strategy\MagicLink\Denied\InvalidToken;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyPayload;
use Componenta\Auth\Token\Token;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class MagicLinkStrategyTest extends TestCase
{
    public function testProviderCannotSubstituteDifferentIdentity(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $token = new Token(
            id: 1,
            subjectId: $subjectId,
            expiresAt: new DateTimeImmutable('@2000'),
            usedAt: null,
            createdAt: new DateTimeImmutable('@500'),
        );
        $manager = $this->createMock(TokenManagerInterface::class);
        $manager->expects(self::once())->method('find')
            ->with('plain-token')
            ->willReturn($token);
        $manager->expects(self::once())->method('consume')
            ->with('plain-token')
            ->willReturn(true);
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willReturn(
            new class implements IdentityInterface {
                public UuidInterface $uuid {
                    get => Uuid::fromString(
                        '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
                    );
                }
            },
        );
        $clock = $this->createStub(DateTimeFactoryInterface::class);
        $clock->method('now')->willReturn(new DateTimeImmutable('@1000'));

        $result = (new MagicLinkStrategy($provider, $manager, $clock))->attempt(
            new VerifyPayload('plain-token'),
            new Context(),
        );

        self::assertInstanceOf(InvalidToken::class, $result->subject);
    }
}
