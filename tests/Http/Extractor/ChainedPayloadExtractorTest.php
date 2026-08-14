<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Extractor;

use Componenta\Auth\Http\Extractor\ChainedPayloadExtractor;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class ChainedPayloadExtractorTest extends TestCase
{
    public function testReturnsFirstSupportedPayloadAndStopsChain(): void
    {
        $calls = new ChainedExtractorCallLog();
        $payload = new \stdClass();
        $extractor = new ChainedPayloadExtractor(
            new ChainedExtractorFixture('first', null, $calls),
            new ChainedExtractorFixture('second', $payload, $calls),
            new ChainedExtractorFixture('third', new \stdClass(), $calls),
        );

        self::assertSame(
            $payload,
            $extractor->extract(new ServerRequestFixture()),
        );
        self::assertSame(['first', 'second'], $calls->names);
    }

    public function testReturnsNullWhenNoExtractorSupportsRequest(): void
    {
        $calls = new ChainedExtractorCallLog();
        $extractor = new ChainedPayloadExtractor(
            new ChainedExtractorFixture('first', null, $calls),
            new ChainedExtractorFixture('second', null, $calls),
        );

        self::assertNull($extractor->extract(new ServerRequestFixture()));
        self::assertSame(['first', 'second'], $calls->names);
    }
}

final class ChainedExtractorCallLog
{
    /** @var list<string> */
    public array $names = [];
}

final readonly class ChainedExtractorFixture implements PayloadExtractorInterface
{
    public function __construct(
        private string $name,
        private ?object $payload,
        private ChainedExtractorCallLog $calls,
    ) {}

    public function extract(ServerRequestInterface $request): ?object
    {
        $this->calls->names[] = $this->name;

        return $this->payload;
    }
}
