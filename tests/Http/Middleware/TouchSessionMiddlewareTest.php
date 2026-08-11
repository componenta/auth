<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Middleware\TouchSessionMiddleware;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TouchSessionMiddlewareTest extends TestCase
{
    public function testDownstreamClearWinsWhenMiddlewareCreatesTransportState(): void
    {
        $now = new DateTimeImmutable('@1000');
        $old = self::session('old-session', $now->modify('-1 second'), $now);
        $new = self::session('new-session', $now->modify('+5 minutes'), $now);
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())
            ->method('regenerate')
            ->with('old-session')
            ->willReturn($new);
        $manager->expects(self::never())->method('find');
        $clock = $this->createStub(DateTimeFactoryInterface::class);
        $clock->method('now')->willReturn($now);
        $response = $this->createStub(ResponseInterface::class);
        $removed = $this->createStub(ResponseInterface::class);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $response)
            ->willReturn($removed);
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($new, $response): ResponseInterface {
                self::assertSame(
                    $new,
                    $request->getAttribute(SessionInterface::class),
                );
                $state = $request->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->clear();

                return $response;
            },
        );
        $request = new ServerRequestFixture(attributes: [
            SessionInterface::class => $old,
        ]);

        $result = (new TouchSessionMiddleware($manager, $clock, $storage))
            ->process($request, $handler);

        self::assertSame($removed, $result);
    }

    public function testNormalTouchReusesResolvedSessionWithoutLookup(): void
    {
        $now = new DateTimeImmutable('@1000');
        $session = self::session(
            'current-session',
            $now->modify('+5 minutes'),
            $now->modify('-2 minutes'),
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::never())->method('find');
        $manager->expects(self::once())
            ->method('touch')
            ->with('current-session', $session->lastActiveAt);
        $clock = $this->createStub(DateTimeFactoryInterface::class);
        $clock->method('now')->willReturn($now);
        $response = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface => $response,
        );
        $storage = $this->createStub(PayloadStorageInterface::class);

        self::assertSame(
            $response,
            (new TouchSessionMiddleware($manager, $clock, $storage))->process(
                new ServerRequestFixture(attributes: [
                    SessionInterface::class => $session,
                ]),
                $handler,
            ),
        );
    }

    private static function session(
        string $id,
        DateTimeImmutable $regenerateAt,
        DateTimeImmutable $lastActiveAt,
    ): SessionInterface {
        $createdAt = new DateTimeImmutable('@800');

        return new Session(
            id: $id,
            subjectId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            expiresAt: new DateTimeImmutable('@2000'),
            absoluteExpiresAt: new DateTimeImmutable('@4000'),
            regenerateAt: $regenerateAt,
            replacedBy: null,
            createdAt: $createdAt,
            lastActiveAt: $lastActiveAt,
        );
    }
}
