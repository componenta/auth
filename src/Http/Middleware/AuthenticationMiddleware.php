<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Authenticates and commits the final credential transport decision once. */
final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private PayloadExtractorInterface $extractor,
        private AuthenticatorInterface $authenticator,
        private ?PayloadStorageInterface $storage = null,
    ) {}

    #[\Override]
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $handler->handle($request);
        }

        $transportState = new CredentialTransportState();
        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
            CredentialTransportState::class => $transportState,
        ]));

        if ($result->transportPayload !== null) {
            $transportState->queue($result->transportPayload);
        }

        $subjectKey = $result->subject instanceof IdentityInterface
            ? IdentityInterface::class
            : DeniedReasonInterface::class;

        $request = $request
            ->withAttribute($subjectKey, $result->subject)
            ->withAttribute(CredentialTransportState::class, $transportState);

        if ($result->session !== null) {
            $request = $request->withAttribute(SessionInterface::class, $result->session);
        }

        $response = $handler->handle($request);

        if ($transportState->empty) {
            return $response;
        }

        if ($this->storage === null) {
            throw new \LogicException(
                'Authentication transport mutation is pending, but no PayloadStorageInterface is configured.',
            );
        }

        return $transportState->apply($this->storage, $request, $response);
    }
}
