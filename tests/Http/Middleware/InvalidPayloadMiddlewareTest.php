<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Middleware\InvalidPayloadMiddleware;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class InvalidPayloadMiddlewareTest extends TestCase
{
    public function testValidDownstreamResponsePassesThroughUnchanged(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::never())->method('createResponse');
        $handler = new CallbackRequestHandler(
            static fn(): ResponseInterface => $response,
        );

        self::assertSame(
            $response,
            (new InvalidPayloadMiddleware($factory))->process(
                new ServerRequestFixture(),
                $handler,
            ),
        );
    }

    public function testInvalidPayloadBecomesNonCacheableJson400(): void
    {
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
            ->with(400)
            ->willReturn($response);
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                throw InvalidPayloadException::invalidField('token');
            },
        );

        self::assertSame(
            $response,
            (new InvalidPayloadMiddleware($factory))->process(
                new ServerRequestFixture(),
                $handler,
            ),
        );
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame(
            ['error' => 'invalid_payload', 'field' => 'token'],
            json_decode($body, true, 512, JSON_THROW_ON_ERROR),
        );
    }

    public function testUnrelatedExceptionIsNotConvertedTo400(): void
    {
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::never())->method('createResponse');
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                throw new \RuntimeException('downstream failure');
            },
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('downstream failure');

        (new InvalidPayloadMiddleware($factory))->process(
            new ServerRequestFixture(),
            $handler,
        );
    }
}
