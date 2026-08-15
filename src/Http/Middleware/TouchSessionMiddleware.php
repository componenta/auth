<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Updates activity only after session authentication and rotation have succeeded. */
final readonly class TouchSessionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionManagerInterface $manager,
    ) {}

    #[\Override]
    public function process(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $identity = $request->getAttribute(IdentityInterface::class);
        $session = $request->getAttribute(SessionInterface::class);

        if (
            $identity instanceof SessionAwareInterface
            && $session instanceof SessionInterface
        ) {
            $this->manager->touch($session->id, $session->lastActiveAt);
        }

        return $handler->handle($request);
    }
}
