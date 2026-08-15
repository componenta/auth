<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Session;

use Componenta\Auth\Context;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Strategy\Session\SessionStrategy;
use Componenta\Auth\Http\Strategy\Session\UserProviderInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionCollectionInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SessionStrategyTest extends TestCase
{
    public function testDueSessionIsRegeneratedBeforeAuthenticationCompletes(): void
    {
        $now = new DateTimeImmutable('@1000');
        $subjectId = self::subjectId();
        $old = self::session('old-session', $subjectId, new DateTimeImmutable('@999'));
        $new = self::session('new-session', $subjectId, new DateTimeImmutable('@1300'));
        $identity = self::identity($subjectId);
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())->method('find')
            ->with('old-session')
            ->willReturn($old);
        $manager->expects(self::once())->method('regenerate')
            ->with('old-session')
            ->willReturn($new);
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects(self::once())->method('findByUuid')
            ->with($subjectId)
            ->willReturn($identity);
        $clock = $this->createStub(DateTimeFactoryInterface::class);
        $clock->method('now')->willReturn($now);

        $result = (new SessionStrategy($manager, $provider, $clock))->attempt(
            new SessionPayload('old-session'),
            new Context(),
        );

        self::assertSame($identity, $result->subject);
        self::assertSame($new, $result->session);
        self::assertInstanceOf(SessionPayload::class, $result->transportPayload);
        self::assertSame('new-session', $result->transportPayload->sessionId);
    }

    public function testConcurrentRegenerationFailsAuthenticationWithoutSuccessorDisclosure(): void
    {
        $now = new DateTimeImmutable('@1000');
        $subjectId = self::subjectId();
        $old = self::session('old-session', $subjectId, new DateTimeImmutable('@999'));
        $identity = self::identity($subjectId);
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->method('find')->willReturn($old);
        $manager->expects(self::once())->method('regenerate')
            ->willThrowException(new ConcurrentRegenerationException());
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $clock = $this->createStub(DateTimeFactoryInterface::class);
        $clock->method('now')->willReturn($now);

        $result = (new SessionStrategy($manager, $provider, $clock))->attempt(
            new SessionPayload('old-session'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertNull($result->session);
        self::assertNull($result->transportPayload);
    }

    public function testManagerCannotBridgePresentedIdToReplacement(): void
    {
        $subjectId = self::subjectId();
        $replacement = self::session(
            'new-session',
            $subjectId,
            new DateTimeImmutable('@1300'),
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->method('find')->with('old-session')->willReturn($replacement);
        $manager->expects(self::never())->method('regenerate');
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects(self::never())->method('findByUuid');
        $clock = $this->createStub(DateTimeFactoryInterface::class);

        $result = (new SessionStrategy($manager, $provider, $clock))->attempt(
            new SessionPayload('old-session'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertNull($result->transportPayload);
    }

    public function testProviderCannotSubstituteDifferentIdentity(): void
    {
        $subjectId = self::subjectId();
        $session = self::session(
            'current-session',
            $subjectId,
            new DateTimeImmutable('@1300'),
        );
        $otherId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->method('find')->willReturn($session);
        $manager->expects(self::never())->method('regenerate');
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('findByUuid')->willReturn(self::identity($otherId));
        $clock = $this->createStub(DateTimeFactoryInterface::class);

        $result = (new SessionStrategy($manager, $provider, $clock))->attempt(
            new SessionPayload('current-session'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertNull($result->session);
        self::assertNull($result->transportPayload);
    }

    private static function session(
        string $id,
        UuidInterface $subjectId,
        DateTimeImmutable $regenerateAt,
    ): SessionInterface {
        return new Session(
            id: $id,
            subjectId: $subjectId,
            expiresAt: new DateTimeImmutable('@2000'),
            absoluteExpiresAt: new DateTimeImmutable('@4000'),
            regenerateAt: $regenerateAt,
            replacedBy: null,
            createdAt: new DateTimeImmutable('@800'),
            lastActiveAt: new DateTimeImmutable('@900'),
        );
    }

    private static function subjectId(): UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    private static function identity(
        UuidInterface $uuid,
    ): IdentityInterface&SessionAwareInterface {
        return new readonly class($uuid, new SessionCollection()) implements IdentityInterface, SessionAwareInterface {
            public function __construct(
                public UuidInterface $uuid,
                public SessionCollectionInterface $sessions,
            ) {}
        };
    }
}
