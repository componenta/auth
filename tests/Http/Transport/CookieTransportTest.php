<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Transport;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Transport\CookieTransport;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class CookieTransportTest extends TestCase
{
    public function testHostPrefixRequiresHostOnlySecureProfile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CookieTransport(name: '__Host-sid', domain: 'example.com');
    }

    public function testNonScalarCookieCredentialIsRejected(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn(['sid' => ['unexpected']]);

        $this->expectException(InvalidPayloadException::class);
        (new CookieTransport())->extract($request);
    }
}
