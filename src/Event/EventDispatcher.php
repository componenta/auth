<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Psr\Log\LoggerInterface;

/**
 * Dispatches authentication and session events to registered listeners.
 *
 * A failing listener must not prevent the remaining ones from running -
 * side effects like "revoke remember-me on logout" should still fire even
 * if an unrelated listener throws. Exceptions are isolated per-listener
 * and reported to the logger when one is provided.
 */
final readonly class EventDispatcher
{
    public function __construct(
        private EventListenerProviderInterface $provider,
        private ?LoggerInterface $logger = null,
    ) {}

    public function dispatch(EventInterface $event): void
    {
        foreach ($this->provider->provideFor($event) as $listener) {
            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logger?->error(
                    'Auth event listener failed',
                    [
                        'event' => $event::class,
                        'listener' => $listener::class,
                        'exception' => $e,
                    ],
                );
            }
        }
    }
}
