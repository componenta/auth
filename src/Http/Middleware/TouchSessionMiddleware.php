<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Updates session last activity timestamp and handles canary regeneration.
 *
 * Should be placed after AuthenticationMiddleware.
 */
final readonly class TouchSessionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionManagerInterface $manager,
        private DateTimeFactoryInterface $dateTimeFactory,
        private ?PayloadStorageInterface $storage = null,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $user = $request->getAttribute(IdentityInterface::class);

        if (!$user instanceof SessionAwareInterface) {
            return $handler->handle($request);
        }

        if ($user->currentSessionId === null) {
            throw new \LogicException(
                'TouchSessionMiddleware requires currentSessionId to be set. '
                . 'Ensure SessionStrategy is configured.',
            );
        }

        $session = $this->manager->find($user->currentSessionId);

        if ($session === null) {
            return $handler->handle($request);
        }

        // Canary: regenerate session ID
        $now = $this->dateTimeFactory->now();

        if ($session->regenerateAt <= $now) {
            $newSession = $this->manager->regenerate($session->id);
            $user->currentSessionId = $newSession->id;

            $response = $handler->handle($request);

            if ($this->storage !== null) {
                $response = $this->storage->store(
                    $request,
                    $response,
                    new SessionPayload($newSession->id),
                );
            }

            return $response;
        }

        // Normal touch: update idle timeout
        $this->manager->touch($session->id);

        return $handler->handle($request);
    }
}
