<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Handler;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\LoggedOut;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LogoutHandler implements RequestHandlerInterface
{
    public function __construct(
        protected PayloadStorageInterface $storage,
        protected SessionManagerInterface $sessionManager,
        protected ResponseFactoryInterface $responseFactory,
        protected ?EventDispatcher $dispatcher = null,
        protected ClockInterface $clock = new Clock(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $transportState = $request->getAttribute(CredentialTransportState::class);

        if ($transportState instanceof CredentialTransportState) {
            $transportState->clear();
        }

        $session = $request->getAttribute(SessionInterface::class);
        $user = $request->getAttribute(IdentityInterface::class);

        if ($session instanceof SessionInterface) {
            $this->sessionManager->terminate($session->id);
        } elseif ($user instanceof SessionAwareInterface && $user->currentSessionId !== null) {
            // Compatibility fallback for application-provided authentication middleware.
            $this->sessionManager->terminate($user->currentSessionId);
        }

        $response = $this->storage->remove(
            $request,
            $this->responseFactory->createResponse(204),
        );

        if ($user instanceof IdentityInterface) {
            $this->dispatcher?->dispatch(new LoggedOut($user, $this->clock->now()));
        }

        return $response;
    }
}
