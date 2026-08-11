<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Middleware;

use Componenta\Auth\Session\SessionCleanupSchedulerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/** Probabilistically schedules best-effort cleanup outside the request. */
final readonly class SessionGarbageCollectionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionCleanupSchedulerInterface $scheduler,
        private int $lottery = 100,
        private ?LoggerInterface $logger = null,
    ) {
        if ($this->lottery < 1) {
            throw new \InvalidArgumentException(
                'Session cleanup lottery must be greater than zero.',
            );
        }
    }

    #[\Override]
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);

        if (random_int(1, $this->lottery) !== 1) {
            return $response;
        }

        try {
            $this->scheduler->schedule();
        } catch (Throwable $exception) {
            $this->logger?->warning(
                'Unable to schedule session cleanup.',
                ['exception' => $exception],
            );
        }

        return $response;
    }
}
