<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Token;

use Componenta\Auth\Token\SenderInterface;
use Componenta\Auth\Token\Token;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestProcessor;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class TokenRequestProcessorTest extends TestCase
{
    public function testProcessorForwardsDestinationAndContextAfterAtomicReplacement(): void
    {
        $identity = new TokenProcessorIdentityFixture();
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects(self::once())
            ->method('findByIdentity')
            ->with('login@example.com')
            ->willReturn($identity);
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::once())
            ->method('replaceForSubject')
            ->with(self::callback(static fn(UuidInterface $uuid): bool =>
                $uuid->equals($identity->uuid)))
            ->willReturn(str_repeat('a', 64));
        $sender = $this->createMock(SenderInterface::class);
        $sender->expects(self::once())
            ->method('send')
            ->with(
                'delivery@example.net',
                str_repeat('a', 64),
                ['redirect' => '/account'],
            );

        (new TokenRequestProcessor($provider, $tokens, $sender))->process(
            new TokenRequest(
                identity: 'login@example.com',
                destination: 'delivery@example.net',
                context: ['redirect' => '/account'],
            ),
        );
    }

    public function testUnknownIdentityPerformsNoTokenOrDeliveryOperation(): void
    {
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByIdentity')->willReturn(null);
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('replaceForSubject');
        $sender = $this->createMock(SenderInterface::class);
        $sender->expects(self::never())->method('send');

        (new TokenRequestProcessor($provider, $tokens, $sender))->process(
            new TokenRequest('unknown@example.com'),
        );
    }
}

final readonly class TokenProcessorIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid;

    public function __construct()
    {
        $this->uuid = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
