<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class ChainedPayloadExtractor implements PayloadExtractorInterface
{
    /** @var PayloadExtractorInterface[] */
    private array $extractors;

    public function __construct(PayloadExtractorInterface ...$extractors)
    {
        $this->extractors = $extractors;
    }

    public function extract(ServerRequestInterface $request): ?object
    {
        foreach ($this->extractors as $extractor) {
            $payload = $extractor->extract($request);

            if ($payload !== null) {
                return $payload;
            }
        }

        return null;
    }
}
