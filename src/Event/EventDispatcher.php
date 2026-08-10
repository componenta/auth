<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Psr\Log\LoggerInterface;

final readonly class EventDispatcher
{
    public function __construct(
        private EventListenerProviderInterface $provider,
        private ?LoggerInterface $logger = null,
    ) {}

    public function dispatch(EventInterface $event): void
    {
        $criticalFailure = null;

        foreach ($this->provider->provideFor($event) as $listener) {
            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logger?->error(
                    'Auth event listener failed',
                    [
                        'event' => $event::class,
                        'listener' => $listener::class,
                        'critical' => $listener instanceof CriticalEventListenerInterface,
                        'exception' => $e,
                    ],
                );

                if ($criticalFailure === null && $listener instanceof CriticalEventListenerInterface) {
                    $criticalFailure = $e;
                }
            }
        }

        if ($criticalFailure instanceof \Throwable) {
            throw $criticalFailure;
        }
    }
}
