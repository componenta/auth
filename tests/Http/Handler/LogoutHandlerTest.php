<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Handler;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
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
        $session = new Session('session', 'user', $now, $now, $now, null, $now, $now);
        $state = new CredentialTransportState();
        $state->queue(new \stdClass());
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(
            static fn(string $name): mixed => match ($name) {
                SessionInterface::class => $session,
                CredentialTransportState::class => $state,
                default => null,
            },
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())->method('terminate')->with('session');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('remove');
        $response = $this->createMock(ResponseInterface::class);
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->method('createResponse')->with(204)->willReturn($response);

        self::assertSame(
            $response,
            (new LogoutHandler($storage, $manager, $responses))->handle($request),
        );
        self::assertTrue($state->cleared);
    }
}
