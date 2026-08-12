<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Token;

use Componenta\Auth\Token\SenderInterface;
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
    public function testProcessorDeliversOnlyToTheIdentityRequested(): void
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
                'login@example.com',
                str_repeat('a', 64),
                ['template' => 'account'],
            );

        (new TokenRequestProcessor(
            $provider,
            $tokens,
            $sender,
            TokenRequest::PURPOSE_MAGIC_LINK,
        ))->process(new TokenRequest(
            identity: 'login@example.com',
            purpose: TokenRequest::PURPOSE_MAGIC_LINK,
            context: ['template' => 'account'],
        ));
    }

    public function testUnknownIdentityPerformsNoTokenOrDeliveryOperation(): void
    {
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByIdentity')->willReturn(null);
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('replaceForSubject');
        $sender = $this->createMock(SenderInterface::class);
        $sender->expects(self::never())->method('send');

        (new TokenRequestProcessor(
            $provider,
            $tokens,
            $sender,
            TokenRequest::PURPOSE_PASSWORD_RESET,
        ))->process(new TokenRequest(
            'unknown@example.com',
            TokenRequest::PURPOSE_PASSWORD_RESET,
        ));
    }

    public function testMisroutedPurposeFailsBeforeProviderTokenOrDeliveryWork(): void
    {
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects(self::never())->method('findByIdentity');
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('replaceForSubject');
        $sender = $this->createMock(SenderInterface::class);
        $sender->expects(self::never())->method('send');
        $processor = new TokenRequestProcessor(
            $provider,
            $tokens,
            $sender,
            TokenRequest::PURPOSE_MAGIC_LINK,
        );

        $this->expectException(\InvalidArgumentException::class);
        $processor->process(new TokenRequest(
            'login@example.com',
            TokenRequest::PURPOSE_PASSWORD_RESET,
        ));
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
