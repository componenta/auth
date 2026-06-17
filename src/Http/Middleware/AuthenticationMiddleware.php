<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Authenticates requests using extractor and authenticator.
 *
 * Extracts payload from request, delegates authentication to the
 * authenticator chain, and stores transport payload (cookies) when
 * a strategy provides one (e.g. remember-me auto-login).
 */
final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private PayloadExtractorInterface $extractor,
        private AuthenticatorInterface $authenticator,
        private ?PayloadStorageInterface $storage = null,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $handler->handle($request);
        }

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        $key = $result->subject instanceof IdentityInterface
            ? IdentityInterface::class : DeniedReasonInterface::class;

        $request = $request->withAttribute($key, $result->subject);
        $response = $handler->handle($request);

        if ($result->transportPayload !== null) {
            if ($this->storage === null) {
                throw new \LogicException(
                    'Strategy returned a transport payload, but no PayloadStorageInterface is configured. '
                    . 'Provide a storage implementation to AuthenticationMiddleware.',
                );
            }

            $response = $this->storage->store($request, $response, $result->transportPayload);
        }

        return $response;
    }
}
