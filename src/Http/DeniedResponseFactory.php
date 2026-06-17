<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\DeniedReasonInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Default implementation mapping denial reasons to JSON responses.
 */
final readonly class DeniedResponseFactory implements DeniedResponseFactoryInterface
{
    /**
     * @param ResponseFactoryInterface $responseFactory PSR-17 response factory
     * @param array<string, int> $statusMap Map of denial codes to HTTP status codes
     * @param int $defaultStatus Default HTTP status code
     */
    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private array $statusMap = [],
        private int $defaultStatus = 401,
    ) {}

    public function create(DeniedReasonInterface $reason): ResponseInterface
    {
        $status = $this->statusMap[$reason->code] ?? $this->defaultStatus;
        $response = $this->responseFactory->createResponse($status);

        try {
            $body = json_encode([
                'error' => $reason->code,
                'details' => $reason->attributes,
            ], JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // attributes carry non-encodable payload (e.g., resource handles).
            // Fall back to a minimal, guaranteed-serializable body so callers
            // never get a 500 from the denial path.
            $body = json_encode(['error' => $reason->code], JSON_THROW_ON_ERROR);
        }

        $response->getBody()->write($body);

        return $response->withHeader('Content-Type', 'application/json');
    }
}
