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

/** Authenticates and commits one shared request-scoped transport decision. */
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

        $existingState = $request->getAttribute(CredentialTransportState::class);
        $ownsTransportState = !$existingState instanceof CredentialTransportState;
        $transportState = $ownsTransportState
            ? new CredentialTransportState()
            : $existingState;
        $request = $request->withAttribute(
            CredentialTransportState::class,
            $transportState,
        );

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
            CredentialTransportState::class => $transportState,
        ]));

        if ($result->transportPayload !== null) {
            $transportState->queue($result->transportPayload);
        }

        // A new authentication result replaces every request-local result from
        // an earlier authentication layer. Keeping both identity and denial (or
        // an unrelated old session) can accidentally authorize the request.
        $request = $request
            ->withoutAttribute(IdentityInterface::class)
            ->withoutAttribute(DeniedReasonInterface::class)
            ->withoutAttribute(SessionInterface::class);

        if ($result->subject instanceof IdentityInterface) {
            $request = $request->withAttribute(
                IdentityInterface::class,
                $result->subject,
            );
        } else {
            $request = $request->withAttribute(
                DeniedReasonInterface::class,
                $result->subject,
            );
        }

        if ($result->session !== null) {
            $request = $request->withAttribute(
                SessionInterface::class,
                $result->session,
            );
        }

        $response = $handler->handle($request);

        if (!$ownsTransportState || $transportState->empty) {
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
