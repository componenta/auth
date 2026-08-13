<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\TokenResponseHeaders;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class TokenResponseHeadersTest extends TestCase
{
    public function testJsonResponseDoesNotInferSemanticsFromBodySize(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(self::never())->method('getBody');
        $response->expects(self::exactly(3))->method('withHeader')->willReturnSelf();
        $response->expects(self::never())->method('withoutHeader');

        self::assertSame($response, TokenResponseHeaders::apply($response));
    }

    public function testEmptyResponseDoesNotInferSemanticsFromBodySize(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(self::never())->method('getBody');
        $response->expects(self::exactly(2))->method('withHeader')->willReturnSelf();
        $response->expects(self::once())->method('withoutHeader')
            ->with('Content-Type')
            ->willReturnSelf();

        self::assertSame($response, TokenResponseHeaders::applyEmpty($response));
    }
}
