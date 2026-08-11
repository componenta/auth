<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\PasswordReset;

use Componenta\Auth\PasswordReset\ForgotPasswordHandler;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class ForgotPasswordHandlerTest extends TestCase
{
    public function testMalformedIdentityReturns400WithoutQueueing(): void
    {
        $queue = $this->createMock(TokenRequestQueueInterface::class);
        $queue->expects(self::never())->method('enqueue');
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'email' => ' user@example.com ',
        ]);
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(400)
            ->willReturn($response);

        self::assertSame(
            $response,
            (new ForgotPasswordHandler($queue, $factory))->handle($request),
        );
    }

    public function testRequestPathOnlyEnqueuesOpaqueWork(): void
    {
        $queue = new PasswordResetQueueFixture();
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn(['email' => 'user@example.com']);
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);

        self::assertSame($response, (new ForgotPasswordHandler($queue, $factory))->handle($request));
        self::assertSame('user@example.com', $queue->request?->identity);
    }
}

final class PasswordResetQueueFixture implements TokenRequestQueueInterface
{
    public ?TokenRequest $request = null;
    public function enqueue(TokenRequest $request): void { $this->request = $request; }
}
