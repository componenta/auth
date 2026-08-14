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
        $calls = [];
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
        self::assertSame(['first', 'second'], $calls);
    }

    public function testReturnsNullWhenNoExtractorSupportsRequest(): void
    {
        $calls = [];
        $extractor = new ChainedPayloadExtractor(
            new ChainedExtractorFixture('first', null, $calls),
            new ChainedExtractorFixture('second', null, $calls),
        );

        self::assertNull($extractor->extract(new ServerRequestFixture()));
        self::assertSame(['first', 'second'], $calls);
    }
}

final class ChainedExtractorFixture implements PayloadExtractorInterface
{
    /** @param list<string> $calls */
    public function __construct(
        private string $name,
        private ?object $payload,
        private array &$calls,
    ) {}

    public function extract(ServerRequestInterface $request): ?object
    {
        $this->calls[] = $this->name;

        return $this->payload;
    }
}
