<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
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
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        // A denial produced by an earlier authentication layer is terminal.
        // Soft-failure continuation belongs inside Authenticator, not between
        // independently composed middleware instances.
        if ($request->getAttribute(DeniedReasonInterface::class) instanceof DeniedReasonInterface) {
            return $handler->handle($request);
        }

        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $handler->handle($request);
        }

        $existingIdentity = $request->getAttribute(IdentityInterface::class);
        $existingSession = $request->getAttribute(SessionInterface::class);
        $existingState = $request->getAttribute(CredentialTransportState::class);
        $ownsTransportState = !$existingState instanceof CredentialTransportState;
        $transportState = $ownsTransportState
            ? new CredentialTransportState()
            : $existingState;

        if ($this->storage !== null) {
            $transportState->register($this->storage);
        }

        $request = $request->withAttribute(
            CredentialTransportState::class,
            $transportState,
        );

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
            CredentialTransportState::class => $transportState,
        ]));

        if (
            $result->subject instanceof IdentityInterface
            && $existingIdentity instanceof IdentityInterface
            && !$result->subject->uuid->equals($existingIdentity->uuid)
        ) {
            // Two independently valid credentials for different principals in
            // one request are ambiguous. Fail closed and do not commit an
            // earlier queued rotation for either principal.
            $transportState->discardQueued();
            $result = new AuthenticationResult(new InvalidCredentials());
        }

        if ($result->subject instanceof DeniedReasonInterface) {
            // A later terminal denial must also cancel credential writes queued
            // by an earlier successful nested authentication layer.
            $transportState->discardQueued();
        } elseif ($result->transportPayload !== null) {
            if ($this->storage === null) {
                // The strategy may already have committed a server-side
                // replacement. Compensate before surfacing configuration error.
                $transportState->discardQueued();
                throw new \LogicException(
                    'Authentication credential mutation requires a PayloadStorageInterface before downstream execution.',
                );
            }

            $transportState->queue($this->storage, $result->transportPayload);
        }

        $request = $request
            ->withoutAttribute(IdentityInterface::class)
            ->withoutAttribute(DeniedReasonInterface::class)
            ->withoutAttribute(SessionInterface::class);

        if ($result->subject instanceof IdentityInterface) {
            $request = $request->withAttribute(
                IdentityInterface::class,
                $result->subject,
            );

            $session = $result->session;

            if (
                $session === null
                && $existingIdentity instanceof IdentityInterface
                && $existingIdentity->uuid->equals($result->subject->uuid)
                && $existingSession instanceof SessionInterface
                && $existingSession->subjectId->equals($result->subject->uuid)
            ) {
                $session = $existingSession;
            }

            if ($session !== null) {
                $request = $request->withAttribute(
                    SessionInterface::class,
                    $session,
                );
            }
        } else {
            $request = $request->withAttribute(
                DeniedReasonInterface::class,
                $result->subject,
            );
        }

        try {
            $response = $handler->handle($request);
        } catch (\Throwable $exception) {
            if ($ownsTransportState) {
                // No response can publish the queued replacement credential.
                $transportState->discardQueued();
            }

            throw $exception;
        }

        if (!$ownsTransportState || $transportState->empty) {
            return $response;
        }

        return $transportState->apply($request, $response);
    }
}
