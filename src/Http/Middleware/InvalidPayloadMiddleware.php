<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Exception\InvalidPayloadException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Converts malformed authentication payloads into a stable 400 response. */
final readonly class InvalidPayloadMiddleware implements MiddlewareInterface
{
    public function __construct(private ResponseFactoryInterface $responseFactory) {}

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            return $handler->handle($request);
        } catch (InvalidPayloadException $e) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(json_encode([
                'error' => 'invalid_payload',
                'field' => $e->field,
            ], JSON_THROW_ON_ERROR));
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }
    }
}
