<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Extractor;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Extractor\BearerExtractor;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BearerExtractorTest extends TestCase
{
    public function testMissingOrDifferentAuthorizationSchemeIsUnsupported(): void
    {
        $extractor = new BearerExtractor();

        self::assertNull($extractor->extract(new ServerRequestFixture()));
        self::assertNull($extractor->extract(
            (new ServerRequestFixture())->withHeader('Authorization', 'Basic abc'),
        ));
    }

    #[DataProvider('malformedHeaders')]
    public function testMalformedBearerCredentialIsRejected(string $header): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new BearerExtractor())->extract(
            (new ServerRequestFixture())->withHeader('Authorization', $header),
        );
    }

    public function testMultipleRequiredSpacesAreAccepted(): void
    {
        $payload = (new BearerExtractor())->extract(
            (new ServerRequestFixture())->withHeader(
                'Authorization',
                'Bearer   abc.DEF',
            ),
        );

        self::assertInstanceOf(BearerPayload::class, $payload);
        self::assertSame('abc.DEF', $payload->token);
    }

    public function testValidCredentialIsExtracted(): void
    {
        $payload = (new BearerExtractor())->extract(
            (new ServerRequestFixture())->withHeader(
                'Authorization',
                'Bearer abc.DEF_123~+/=',
            ),
        );

        self::assertInstanceOf(BearerPayload::class, $payload);
        self::assertSame('abc.DEF_123~+/=', $payload->token);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedHeaders(): iterable
    {
        yield 'missing space' => ['Bearer'];
        yield 'tab separator' => ["Bearer\tabc"];
        yield 'empty credential' => ['Bearer '];
        yield 'embedded whitespace' => ['Bearer abc def'];
        yield 'invalid alphabet' => ['Bearer abc?def'];
    }
}
