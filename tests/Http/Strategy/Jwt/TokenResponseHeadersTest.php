<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\TokenResponseHeaders;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class TokenResponseHeadersTest extends TestCase
{
    public function testEmptyBodyDoesNotClaimJsonContentType(): void
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('getSize')->willReturn(0);
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($body);
        $response->expects(self::exactly(2))->method('withHeader')->willReturnSelf();
        $response->expects(self::once())->method('withoutHeader')
            ->with('Content-Type')
            ->willReturnSelf();

        self::assertSame($response, TokenResponseHeaders::apply($response));
    }

    public function testNonEmptyBodyKeepsJsonContentType(): void
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('getSize')->willReturn(2);
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($body);
        $response->expects(self::exactly(3))->method('withHeader')->willReturnSelf();
        $response->expects(self::never())->method('withoutHeader');

        self::assertSame($response, TokenResponseHeaders::apply($response));
    }
}
