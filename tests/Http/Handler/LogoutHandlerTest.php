<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Handler;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\Uuid;
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
        $storage = $this->createMock(PayloadStorageInterface::class);
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(
            static fn(string $name): mixed => match ($name) {
                SessionInterface::class => $session,
                CredentialTransportState::class => $state,
                default => null,
            },
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())->method('terminate')->with('session');
        $storage->expects(self::never())->method('remove');
        $response = $this->createStub(ResponseInterface::class);
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
}
