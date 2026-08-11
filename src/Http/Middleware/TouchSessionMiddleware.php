<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Reuses the verified session and commits regeneration through shared state. */
final readonly class TouchSessionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionManagerInterface $manager,
        private DateTimeFactoryInterface $dateTimeFactory,
        private PayloadStorageInterface $storage,
    ) {}

    #[\Override]
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $session = $request->getAttribute(SessionInterface::class);

        if (!$session instanceof SessionInterface) {
            return $handler->handle($request);
        }

        $now = $this->dateTimeFactory->now();

        if ($session->regenerateAt > $now) {
            $this->manager->touch($session->id, $session->lastActiveAt);

            return $handler->handle($request);
        }

        $newSession = $this->manager->regenerate($session->id);
        $existingState = $request->getAttribute(CredentialTransportState::class);
        $ownsTransportState = !$existingState instanceof CredentialTransportState;
        $transportState = $ownsTransportState
            ? new CredentialTransportState()
            : $existingState;
        $transportState->queue(new SessionPayload($newSession->id));

        $request = $request
            ->withAttribute(SessionInterface::class, $newSession)
            ->withAttribute(CredentialTransportState::class, $transportState);
        $response = $handler->handle($request);

        if (!$ownsTransportState || $transportState->empty) {
            return $response;
        }

        return $transportState->apply($this->storage, $request, $response);
    }
}
