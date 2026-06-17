<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts bearer token from Authorization header.
 *
 * Expects format: Authorization: Bearer <token>
 */
final readonly class BearerExtractor implements PayloadExtractorInterface
{
    /**
     * @param string $header Header name to extract from
     */
    public function __construct(
        public string $header = 'Authorization',
    ) {}

    public function extract(ServerRequestInterface $request): ?object
    {
        $value = $request->getHeaderLine($this->header);

        if ($value === '') {
            return null;
        }

        // RFC 6750 §2.1: the "Bearer" scheme name is case-insensitive.
        if (strlen($value) < 7 || strcasecmp(substr($value, 0, 7), 'Bearer ') !== 0) {
            return null;
        }

        $token = ltrim(substr($value, 7));

        if ($token === '') {
            return null;
        }

        return new BearerPayload($token);
    }
}
