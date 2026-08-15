<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Transport;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Exception\TransportException;
use Componenta\Auth\Http\Transport\CookieTransport;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CookieTransportTest extends TestCase
{
    public function testHostPrefixRequiresHostOnlySecureProfile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CookieTransport(name: '__Host-sid', domain: 'example.com');
    }

    public function testControlCharacterInCookieCredentialIsRejected(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn([
            'sid' => "session\nvalue",
        ]);

        $this->expectException(InvalidPayloadException::class);
        (new CookieTransport())->extract($request);
    }

    public function testNonScalarCookieCredentialIsRejected(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn(['sid' => ['unexpected']]);

        $this->expectException(InvalidPayloadException::class);
        (new CookieTransport())->extract($request);
    }

    public function testRememberCredentialRequiresConfiguredCookieName(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(TransportException::class);
        (new CookieTransport())->store(
            $request,
            $response,
            new SessionPayload('session-id', str_repeat('a', 64)),
        );
    }

    public function testCookieExpiryUsesInjectedClock(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getHeader')->with('Set-Cookie')->willReturn([]);
        $response->method('withoutHeader')->with('Set-Cookie')->willReturnSelf();
        $response->expects(self::once())
            ->method('withAddedHeader')
            ->with(
                'Set-Cookie',
                self::callback(static fn(string $value): bool => str_contains(
                    $value,
                    'Expires=Thu, 01 Jan 1970 00:16:50 GMT',
                ) && str_contains($value, 'Max-Age=10')),
            )
            ->willReturnSelf();

        $result = (new CookieTransport(
            ttl: 10,
            clock: new FrozenClock(1000, 'Europe/Copenhagen'),
        ))->store(
            $request,
            $response,
            new SessionPayload('session-id'),
        );

        self::assertSame($response, $result);
    }
}
