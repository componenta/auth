<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\Http\Middleware\TouchSessionMiddleware;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionCollectionInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TouchSessionMiddlewareTest extends TestCase
{
    public function testVerifiedSessionIsTouchedWithoutRegeneration(): void
    {
        $session = self::session('current-session');
        $identity = self::identity();
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())
            ->method('touch')
            ->with('current-session', $session->lastActiveAt);
        $manager->expects(self::never())->method('regenerate');
        $response = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($session, $response): ResponseInterface {
                self::assertSame(
                    $session,
                    $request->getAttribute(SessionInterface::class),
                );

                return $response;
            },
        );

        $result = (new TouchSessionMiddleware($manager))->process(
            new ServerRequestFixture(attributes: [
                IdentityInterface::class => $identity,
                SessionInterface::class => $session,
            ]),
            $handler,
        );

        self::assertSame($response, $result);
    }

    public function testSessionWithoutSessionAwareIdentityDoesNotTouchStorage(): void
    {
        $session = self::session('current-session');
        $identity = new readonly class(self::subjectId()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::never())->method('touch');
        $manager->expects(self::never())->method('regenerate');
        $response = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface => $response,
        );

        self::assertSame(
            $response,
            (new TouchSessionMiddleware($manager))->process(
                new ServerRequestFixture(attributes: [
                    IdentityInterface::class => $identity,
                    SessionInterface::class => $session,
                ]),
                $handler,
            ),
        );
    }

    public function testRequestWithoutVerifiedSessionDoesNotTouchStorage(): void
    {
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::never())->method('touch');
        $manager->expects(self::never())->method('regenerate');
        $response = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface => $response,
        );

        self::assertSame(
            $response,
            (new TouchSessionMiddleware($manager))->process(
                new ServerRequestFixture(),
                $handler,
            ),
        );
    }

    private static function identity(): IdentityInterface&SessionAwareInterface
    {
        return new readonly class(self::subjectId(), new SessionCollection()) implements IdentityInterface, SessionAwareInterface {
            public function __construct(
                public UuidInterface $uuid,
                public SessionCollectionInterface $sessions,
            ) {}
        };
    }

    private static function subjectId(): UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    private static function session(string $id): SessionInterface
    {
        return new Session(
            id: $id,
            subjectId: self::subjectId(),
            expiresAt: new DateTimeImmutable('@2000'),
            absoluteExpiresAt: new DateTimeImmutable('@4000'),
            regenerateAt: new DateTimeImmutable('@999'),
            replacedBy: null,
            createdAt: new DateTimeImmutable('@800'),
            lastActiveAt: new DateTimeImmutable('@900'),
        );
    }
}
