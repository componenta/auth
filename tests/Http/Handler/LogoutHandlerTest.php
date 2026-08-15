<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Handler;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionCollectionInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LogoutHandlerTest extends TestCase
{
    public function testTerminalMiddlewareOwnsTheOnlyCookieRemoval(): void
    {
        $now = new DateTimeImmutable('@1000');
        $session = new Session(
            'session',
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
        $identity = self::sessionAwareIdentity($session->subjectId);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(
            static fn(string $name): mixed => match ($name) {
                IdentityInterface::class => $identity,
                SessionInterface::class => $session,
                CredentialTransportState::class => $state,
                default => null,
            },
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())->method('terminate')->with('session');
        $storage->expects(self::never())->method('remove');
        $response = $this->responseStub();
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::once())
            ->method('createResponse')
            ->with(204)
            ->willReturn($response);

        self::assertSame(
            $response,
            (new LogoutHandler($storage, $manager, $responses))->handle($request),
        );
        self::assertTrue($state->cleared);
    }

    public function testSessionWithoutSessionAwareIdentityIsNotTerminated(): void
    {
        $now = new DateTimeImmutable('@1000');
        $session = new Session(
            'session',
            self::subjectId(),
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
        $identity = new readonly class($session->subjectId) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(
            static fn(string $name): mixed => match ($name) {
                IdentityInterface::class => $identity,
                SessionInterface::class => $session,
                default => null,
            },
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::never())->method('terminate');
        $response = $this->responseStub();
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('remove')->willReturn($response);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);

        self::assertSame(
            $response,
            (new LogoutHandler($storage, $manager, $responses))->handle($request),
        );
    }

    public function testStandaloneCredentialRemovalIsNonCacheable(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturn(null);
        $response = $this->responseStub();
        $removed = $this->createStub(ResponseInterface::class);
        $headers = [];
        $removed->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $removed): ResponseInterface {
                $headers[$name] = $value;

                return $removed;
            },
        );
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('remove')->willReturn($removed);
        $manager = $this->createStub(SessionManagerInterface::class);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);

        self::assertSame(
            $removed,
            (new LogoutHandler($storage, $manager, $responses))->handle($request),
        );
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
    }

    private static function sessionAwareIdentity(
        UuidInterface $uuid,
    ): IdentityInterface&SessionAwareInterface {
        return new readonly class($uuid, new SessionCollection()) implements IdentityInterface, SessionAwareInterface {
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

    private function responseStub(): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();

        return $response;
    }
}
