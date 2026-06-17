<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Handler;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\LoggedOut;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles logout requests.
 *
 * Extracts the session from the request, terminates it,
 * removes cookies, and dispatches the LoggedOut event.
 *
 * Associated credentials (remember-me tokens, etc.) are cleaned up
 * automatically via session termination listeners.
 *
 * Expects the authenticated user to be available as a request
 * attribute (set by AuthenticationMiddleware).
 */
readonly class LogoutHandler implements RequestHandlerInterface
{
    public function __construct(
        protected PayloadStorageInterface   $storage,
        protected SessionManagerInterface   $sessionManager,
        protected ResponseFactoryInterface  $responseFactory,
        protected ?EventDispatcher          $dispatcher = null,
        protected ClockInterface            $clock = new Clock(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(204);

        // Use the resolved (leaf) session ID from the authenticated user,
        // not the raw cookie value which may point to a replaced session.
        $user = $request->getAttribute(IdentityInterface::class);

        if ($user instanceof SessionAwareInterface && $user->currentSessionId !== null) {
            $this->sessionManager->terminate($user->currentSessionId);
        }

        // Transport clears both session and remember-me cookies
        $response = $this->storage->remove($request, $response);

        if ($user instanceof IdentityInterface) {
            $this->dispatcher?->dispatch(new LoggedOut($user, $this->clock->now()));
        }

        return $response;
    }
}
