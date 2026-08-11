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
            new ServerRequestFixture(parsedBody: []),
        ));
    }

    public function testArrayTokenIsRejectedInsteadOfCausingTypeError(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new VerifyExtractor())->extract(new ServerRequestFixture(
            queryParams: ['token' => ['unexpected']],
        ));
    }

    public function testNonArrayParsedBodyIsRejected(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new VerifyExtractor())->extract(new ServerRequestFixture(
            parsedBody: new \stdClass(),
        ));
    }

    public function testQueryCredentialTakesPrecedenceOverBody(): void
    {
        $payload = (new VerifyExtractor())->extract(new ServerRequestFixture(
            queryParams: ['token' => self::TOKEN],
            parsedBody: ['token' => str_repeat('b', 64)],
        ));

        self::assertInstanceOf(VerifyPayload::class, $payload);
        self::assertSame(self::TOKEN, $payload->token);
    }
}
