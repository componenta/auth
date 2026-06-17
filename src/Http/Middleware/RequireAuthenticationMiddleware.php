<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Requires authenticated user to proceed.
 *
 * Returns denial response if user is not authenticated.
 * Should be placed after AuthenticationMiddleware.
 */
final readonly class RequireAuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private DeniedResponseFactoryInterface $deniedResponseFactory,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $user = $request->getAttribute(IdentityInterface::class);

        if ($user instanceof IdentityInterface) {
            return $handler->handle($request);
        }

        $reason = $request->getAttribute(DeniedReasonInterface::class);

        // No payload was present - unauthorized
        return $this->deniedResponseFactory->create($reason instanceof DeniedReasonInterface
            ? $reason : new Unauthorized()
        );
    }
}
