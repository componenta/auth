<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\PublicDeniedReasonInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/** Default implementation mapping denial reasons to minimal JSON responses. */
final readonly class DeniedResponseFactory implements DeniedResponseFactoryInterface
{
    /**
     * @param array<string, int> $statusMap
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
        $payload = ['error' => $reason->code];

        if ($reason instanceof PublicDeniedReasonInterface) {
            $details = $reason->publicDetails();
            if ($details !== []) {
                $payload['details'] = $details;
            }
        }

        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
