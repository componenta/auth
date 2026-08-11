<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\Http\Strategy\MagicLink\RequestHandler;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class RequestHandlerTest extends TestCase
{
    public function testMalformedIdentityReturns400WithoutQueueing(): void
    {
        $this->assertRejected([
            'identity' => ' user@example.com ',
        ]);
    }

    public function testRedirectIsRejectedWithoutQueueing(): void
    {
        $this->assertRejected([
            'identity' => 'user@example.com',
            'redirect' => 'https://attacker.example/after-login',
        ]);
    }

    public function testValidRequestQueuesNoUntrustedContext(): void
    {
        $queue = $this->createMock(TokenRequestQueueInterface::class);
        $queue->expects(self::once())
            ->method('enqueue')
            ->with(self::callback(static function (TokenRequest $request): bool {
                return $request->identity === 'user@example.com'
                    && $request->context === [];
            }));
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'identity' => 'user@example.com',
        ]);
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

        self::assertSame(
            $response,
            (new RequestHandler($queue, $factory))->handle($request),
        );
    }

    /** @param array<string, mixed> $body */
    private function assertRejected(array $body): void
    {
        $queue = $this->createMock(TokenRequestQueueInterface::class);
        $queue->expects(self::never())->method('enqueue');
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn($body);
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
            (new RequestHandler($queue, $factory))->handle($request),
        );
    }
}
