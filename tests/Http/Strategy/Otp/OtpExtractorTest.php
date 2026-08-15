<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpPayload;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;

final class OtpExtractorTest extends TestCase
{
    public function testFullyAbsentCredentialIsUnsupported(): void
    {
        $extractor = new OtpExtractor(new OtpConfig());

        self::assertNull($extractor->extract(new ServerRequestFixture()));
        self::assertNull($extractor->extract(
            new ServerRequestFixture(parsedBody: []),
        ));
    }

    public function testPartialCredentialIsRejected(): void
    {
        try {
            (new OtpExtractor(new OtpConfig()))->extract(new ServerRequestFixture(
                parsedBody: ['destination' => 'user@example.com'],
            ));
            self::fail('Partial OTP credentials were accepted.');
        } catch (InvalidPayloadException $exception) {
            self::assertSame('code', $exception->field);
        }
    }

    public function testArrayCodeIsRejectedBeforePayloadConstruction(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new OtpExtractor(new OtpConfig()))->extract(new ServerRequestFixture(parsedBody: [
            'destination' => 'user@example.com',
            'code' => ['123456'],
        ]));
    }

    public function testConfiguredLengthIsEnforcedBeforeAttemptAccounting(): void
    {
        $extractor = new OtpExtractor(new OtpConfig(length: 8));

        try {
            $extractor->extract(new ServerRequestFixture(parsedBody: [
                'destination' => 'user@example.com',
                'code' => '123456',
            ]));
            self::fail('A code with the wrong configured length was accepted.');
        } catch (InvalidPayloadException $exception) {
            self::assertSame('code', $exception->field);
        }

        $payload = $extractor->extract(new ServerRequestFixture(parsedBody: [
            'destination' => 'user@example.com',
            'code' => '12345678',
        ]));
        self::assertInstanceOf(OtpPayload::class, $payload);
    }

    public function testValidCredentialsAreExtracted(): void
    {
        $payload = (new OtpExtractor(new OtpConfig()))->extract(new ServerRequestFixture(
            parsedBody: [
                'destination' => 'user@example.com',
                'code' => '123456',
            ],
        ));

        self::assertInstanceOf(OtpPayload::class, $payload);
        self::assertSame('user@example.com', $payload->destination);
        self::assertSame('123456', $payload->code);
    }
}
