<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Http\Strategy\Otp\OtpRequest;
use Componenta\Auth\Http\Strategy\Otp\OtpRequestQueueInterface;
use Componenta\Auth\Http\Strategy\Otp\RequestHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class RequestHandlerTest extends TestCase
{
    public function testMalformedIdentityReturns400WithoutQueueing(): void
    {
        $queue = $this->createMock(OtpRequestQueueInterface::class);
        $queue->expects(self::never())->method('enqueue');
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'destination' => "user\n@example.com",
        ]);
        $response = self::response($this);
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

    private static function response(TestCase $test): ResponseInterface
    {
        $stream = $test->createStub(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $test->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();

        return $response;
    }
}
