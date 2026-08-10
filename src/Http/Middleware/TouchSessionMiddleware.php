<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Uses the session already resolved by SessionStrategy/RememberMeStrategy.
 */
final readonly class TouchSessionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionManagerInterface $manager,
        private DateTimeFactoryInterface $dateTimeFactory,
        private PayloadStorageInterface $storage,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $session = $request->getAttribute(SessionInterface::class);

        if (!$session instanceof SessionInterface) {
            return $handler->handle($request);
        }

        $user = $request->getAttribute(IdentityInterface::class);
        $now = $this->dateTimeFactory->now();

        if ($session->regenerateAt <= $now) {
            $newSession = $this->manager->regenerate($session->id);

            if ($user instanceof SessionAwareInterface) {
                $user->currentSessionId = $newSession->id;
            }

            $request = $request->withAttribute(SessionInterface::class, $newSession);
            $payload = new SessionPayload($newSession->id);
            $transportState = $request->getAttribute(CredentialTransportState::class);

            if ($transportState instanceof CredentialTransportState) {
                $transportState->queue($payload);

                return $handler->handle($request);
            }

            return $this->storage->store(
                $request,
                $handler->handle($request),
                $payload,
            );
        }

        $this->manager->touch($session->id, $session->lastActiveAt);

        return $handler->handle($request);
    }
}
