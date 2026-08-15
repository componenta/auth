<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyPayload;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;

final class VerifyExtractorTest extends TestCase
{
    private const string TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testFullyAbsentCredentialIsUnsupported(): void
    {
        $extractor = new VerifyExtractor();

        self::assertNull($extractor->extract(new ServerRequestFixture()));
        self::assertNull($extractor->extract(
            new ServerRequestFixture(method: 'POST', parsedBody: []),
        ));
    }

    public function testArrayTokenIsRejectedInsteadOfCausingTypeError(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new VerifyExtractor())->extract(new ServerRequestFixture(
            method: 'POST',
            parsedBody: ['token' => ['unexpected']],
        ));
    }

    public function testNonArrayParsedBodyIsRejected(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new VerifyExtractor())->extract(new ServerRequestFixture(
            method: 'POST',
            parsedBody: new \stdClass(),
        ));
    }

    public function testGetQueryCredentialIsNeverExtracted(): void
    {
        $request = new ServerRequestFixture(
            method: 'GET',
            queryParams: ['token' => self::TOKEN],
        );

        self::assertNull((new VerifyExtractor())->extract($request));
    }

    public function testPostBodyCredentialIsExtracted(): void
    {
        $payload = (new VerifyExtractor())->extract(new ServerRequestFixture(
            method: 'POST',
            parsedBody: ['token' => self::TOKEN],
        ));

        self::assertInstanceOf(VerifyPayload::class, $payload);
        self::assertSame(self::TOKEN, $payload->token);
    }
}
