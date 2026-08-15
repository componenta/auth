<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\TokenResponseHeaders;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class TokenResponseHeadersTest extends TestCase
{
    public function testJsonResponseHasExplicitJsonAndNoStoreHeaders(): void
    {
        $headers = [];
        $response = $this->response($headers);

        self::assertSame($response, TokenResponseHeaders::apply($response));
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
    }

    public function testEmptyResponseHasNoContentTypeWhenBodySizeIsUnknown(): void
    {
        $headers = ['Content-Type' => 'text/plain'];
        $response = $this->response($headers);

        self::assertSame($response, TokenResponseHeaders::applyEmpty($response));
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertArrayNotHasKey('Content-Type', $headers);
    }

    /** @param array<string, string> $headers */
    private function response(array &$headers): ResponseInterface
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('getSize')->willReturn(null);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($body);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = $value;

                return $response;
            },
        );
        $response->method('withoutHeader')->willReturnCallback(
            static function (string $name) use (&$headers, $response): ResponseInterface {
                unset($headers[$name]);

                return $response;
            },
        );

        return $response;
    }
}
