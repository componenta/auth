<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Probabilistic garbage collection for expired sessions.
 *
 * On each request, rolls a 1-in-$lottery chance to run cleanup.
 * Place anywhere in the pipeline - cleanup runs after the handler.
 */
final readonly class SessionGarbageCollectionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionManagerInterface $sessionManager,
        private int $lottery = 100,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);

        if (random_int(1, $this->lottery) === 1) {
            $this->sessionManager->cleanup();
        }

        return $response;
    }
}
