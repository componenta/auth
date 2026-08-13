<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\BearerCredential;
use Componenta\Auth\Http\Strategy\Jwt\Claims;
use Componenta\Auth\Http\Strategy\Jwt\HmacSigner;
use PHPUnit\Framework\TestCase;

final class HmacSignerTest extends TestCase
{
    private const string SECRET = 'componenta-auth-hmac-signer-test-secret-32-bytes-minimum';

    public function testSignedAccessTokenFitsSharedBearerContract(): void
    {
        $signer = new HmacSigner(self::SECRET);
        $claims = $this->claims();

        $token = $signer->sign($claims);

        self::assertTrue(BearerCredential::isValid($token));
        self::assertEquals($claims, $signer->parse($token));
    }

    public function testSignerRejectsTokenThatItsOwnBearerContractCannotTransport(): void
    {
        $signer = new HmacSigner(self::SECRET);

        $this->expectException(\InvalidArgumentException::class);
        $signer->sign($this->claims([
            'blob' => str_repeat('x', 10000),
        ]));
    }

    public function testParserRejectsOversizedBearerBeforeJwtParsing(): void
    {
        $signer = new HmacSigner(self::SECRET);

        self::assertNull($signer->parse(
            str_repeat('a', BearerCredential::MAX_LENGTH + 1),
        ));
    }

    /** @param array<string, mixed> $custom */
    private function claims(array $custom = []): Claims
    {
        return new Claims(
            subject: '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            issuedAt: 1000,
            expiresAt: 1900,
            issuer: 'https://issuer.example',
            audience: 'componenta-api',
            custom: $custom,
        );
    }
}
