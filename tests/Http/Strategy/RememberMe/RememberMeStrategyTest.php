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
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionInterface;
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
        $subjectId = self::subjectId();
        $rotation = self::rotation($subjectId);
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

    public function testProviderFailureRevokesUnpublishedSuccessor(): void
    {
        $rotation = self::rotation(self::subjectId());
        $manager = $this->createMock(RememberMeTokenManagerInterface::class);
        $manager->expects(self::once())->method('rotate')
            ->willReturn($rotation);
        $manager->expects(self::once())->method('revoke')
            ->with($rotation->successorToken);
        $manager->expects(self::never())->method('bindRotation');
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('find');
        $sessions->expects(self::never())->method('create');
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willThrowException(
            new \RuntimeException('provider unavailable'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('provider unavailable');

        (new RememberMeStrategy($manager, $sessions, $provider))->attempt(
            new SessionPayload(rememberMeToken: 'remember-secret'),
            new Context(),
        );
    }

    public function testBindFailureRevokesSuccessorAndTerminatesUnpublishedSession(): void
    {
        $subjectId = self::subjectId();
        $rotation = self::rotation($subjectId);
        $session = self::session($subjectId);
        $manager = $this->createMock(RememberMeTokenManagerInterface::class);
        $manager->expects(self::once())->method('rotate')->willReturn($rotation);
        $manager->expects(self::once())->method('bindRotation')
            ->with($rotation, $session->id)
            ->willThrowException(new \RuntimeException('bind failed'));
        $manager->expects(self::once())->method('revoke')
            ->with($rotation->successorToken);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::once())->method('find')
            ->with($rotation->previousSessionId)
            ->willReturn(null);
        $sessions->expects(self::once())->method('create')
            ->with(self::callback(static fn(UuidInterface $uuid): bool =>
                $uuid->equals($subjectId)), [])
            ->willReturn($session);
        $sessions->expects(self::once())->method('terminate')
            ->with($session->id);
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willReturn(
            new RememberMeIdentityFixture($subjectId),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('bind failed');

        (new RememberMeStrategy($manager, $sessions, $provider))->attempt(
            new SessionPayload(rememberMeToken: 'remember-secret'),
            new Context(),
        );
    }

    public function testRejectedBindRevokesSuccessorAndTerminatesUnpublishedSession(): void
    {
        $subjectId = self::subjectId();
        $rotation = self::rotation($subjectId);
        $session = self::session($subjectId);
        $manager = $this->createMock(RememberMeTokenManagerInterface::class);
        $manager->expects(self::once())->method('rotate')->willReturn($rotation);
        $manager->expects(self::once())->method('bindRotation')
            ->with($rotation, $session->id)
            ->willReturn(false);
        $manager->expects(self::once())->method('revoke')
            ->with($rotation->successorToken);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::once())->method('find')->willReturn(null);
        $sessions->expects(self::once())->method('create')->willReturn($session);
        $sessions->expects(self::once())->method('terminate')
            ->with($session->id);
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willReturn(
            new RememberMeIdentityFixture($subjectId),
        );

        $result = (new RememberMeStrategy(
            $manager,
            $sessions,
            $provider,
        ))->attempt(
            new SessionPayload(rememberMeToken: 'remember-secret'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertNull($result->session);
        self::assertNull($result->transportPayload);
    }

    private static function subjectId(): UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    private static function rotation(UuidInterface $subjectId): RememberMeRotation
    {
        return new RememberMeRotation(
            $subjectId,
            'old-session',
            str_repeat('a', 64),
            new DateTimeImmutable('@2000'),
        );
    }

    private static function session(UuidInterface $subjectId): SessionInterface
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            'new-session',
            $subjectId,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
    }
}

final readonly class RememberMeIdentityFixture implements IdentityInterface
{
    public function __construct(public UuidInterface $uuid) {}
}
