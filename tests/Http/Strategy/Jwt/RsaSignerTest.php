<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\BearerCredential;
use Componenta\Auth\Http\Strategy\Jwt\Claims;
use Componenta\Auth\Http\Strategy\Jwt\RsaSigner;
use PHPUnit\Framework\TestCase;

final class RsaSignerTest extends TestCase
{
    public function testSignedAccessTokenFitsSharedBearerContract(): void
    {
        [$publicKey, $privateKey] = self::keyPair();
        $signer = new RsaSigner($publicKey, $privateKey);
        $claims = self::claims();

        $token = $signer->sign($claims);

        self::assertTrue(BearerCredential::isValid($token));
        self::assertEquals($claims, $signer->parse($token));
    }

    public function testSignerRejectsTokenThatBearerTransportCannotTransport(): void
    {
        [$publicKey, $privateKey] = self::keyPair();
        $signer = new RsaSigner($publicKey, $privateKey);

        $this->expectException(\InvalidArgumentException::class);

        $signer->sign(self::claims([
            'blob' => str_repeat('x', 10000),
        ]));
    }

    /** @param array<string, mixed> $custom */
    private static function claims(array $custom = []): Claims
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

    /** @return array{string, string} */
    private static function keyPair(): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new \RuntimeException('Unable to create RSA test key.');
        }

        $privateKey = '';
        if (!openssl_pkey_export($key, $privateKey)) {
            throw new \RuntimeException('Unable to export RSA test private key.');
        }

        $details = openssl_pkey_get_details($key);
        $publicKey = is_array($details) ? ($details['key'] ?? null) : null;

        if (!is_string($publicKey) || $publicKey === '') {
            throw new \RuntimeException('Unable to export RSA test public key.');
        }

        return [$publicKey, $privateKey];
    }
}
