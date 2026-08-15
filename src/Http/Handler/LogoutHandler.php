<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Handler;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\LoggedOut;
use Componenta\Auth\Http\CredentialResponseHeaders;
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

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $session = $request->getAttribute(SessionInterface::class);
        $identity = $request->getAttribute(IdentityInterface::class);

        if (
            $identity instanceof SessionAwareInterface
            && $session instanceof SessionInterface
        ) {
            $this->sessionManager->terminate($session->id);
        }

        $response = $this->responseFactory->createResponse(204);
        $transportState = $request->getAttribute(CredentialTransportState::class);

        if ($transportState instanceof CredentialTransportState) {
            $transportState->clear($this->storage);
        } else {
            $response = $this->storage->remove($request, $response);
        }

        if ($identity instanceof IdentityInterface) {
            $this->dispatcher?->dispatchObservers(
                new LoggedOut($identity->uuid, $this->clock->now()),
            );
        }

        return CredentialResponseHeaders::apply($response);
    }
}
