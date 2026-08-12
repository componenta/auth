<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\RememberMe;

use Componenta\Auth\Context;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\UserProviderInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class RememberMeStrategyTest extends TestCase
{
    public function testProviderCannotSubstituteDifferentIdentity(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $rotation = new RememberMeRotation(
            $subjectId,
            'old-session',
            str_repeat('a', 64),
            new DateTimeImmutable('@2000'),
        );
        $manager = $this->createMock(RememberMeTokenManagerInterface::class);
        $manager->expects(self::once())->method('rotate')
            ->with('remember-secret')
            ->willReturn($rotation);
        $manager->expects(self::once())->method('revoke')
            ->with($rotation->successorToken);
        $manager->expects(self::never())->method('bindRotation');
        $sessionManager = $this->createMock(SessionManagerInterface::class);
        $sessionManager->expects(self::never())->method('find');
        $sessionManager->expects(self::never())->method('create');
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

        $result = (new RememberMeStrategy(
            $manager,
            $sessionManager,
            $provider,
        ))->attempt(
            new SessionPayload(rememberMeToken: 'remember-secret'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertNull($result->session);
        self::assertNull($result->transportPayload);
    }
}
