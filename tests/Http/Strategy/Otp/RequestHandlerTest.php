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

    public function testValidIdentityQueuesRequestAndReturnsNonCacheableJson(): void
    {
        $queue = new OtpRequestQueueFixture();
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'destination' => 'user@example.com',
        ]);
        $headers = [];
        $body = '';
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $chunk) use (&$body): int {
                $body .= $chunk;

                return strlen($chunk);
            },
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = $value;

                return $response;
            },
        );
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);

        self::assertSame(
            $response,
            (new RequestHandler($queue, $factory))->handle($request),
        );
        self::assertInstanceOf(OtpRequest::class, $queue->request);
        self::assertSame('user@example.com', $queue->request->identity);
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);

        $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertIsString($decoded['message'] ?? null);
        self::assertNotSame('', $decoded['message']);
    }

    public function testResponseConstructionCompletesBeforeDurableQueueing(): void
    {
        $queue = $this->createMock(OtpRequestQueueInterface::class);
        $queue->expects(self::never())->method('enqueue');
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'destination' => 'user@example.com',
        ]);
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static fn() => throw new \RuntimeException('response write failed'),
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory->method('createResponse')->willReturn($response);

        $this->expectException(\RuntimeException::class);

        (new RequestHandler($queue, $factory))->handle($request);
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

final class OtpRequestQueueFixture implements OtpRequestQueueInterface
{
    public ?OtpRequest $request = null;

    public function enqueue(OtpRequest $request): void
    {
        $this->request = $request;
    }
}
