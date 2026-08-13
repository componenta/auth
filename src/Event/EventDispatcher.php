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
        $this->dispatchCritical($event);
        $this->dispatchBestEffort($event);
    }

    public function dispatchCritical(EventInterface $event): void
    {
        foreach ($this->provider->provideFor($event) as $listener) {
            if (!$listener instanceof CriticalEventListenerInterface) {
                continue;
            }

            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logFailure($event, $listener, $e, true);
                throw $e;
            }
        }
    }

    public function dispatchBestEffort(EventInterface $event): void
    {
        foreach ($this->provider->provideFor($event) as $listener) {
            if ($listener instanceof CriticalEventListenerInterface) {
                continue;
            }

            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logFailure($event, $listener, $e, false);
            }
        }
    }

    public function dispatchObservers(EventInterface $event): void
    {
        foreach ($this->provider->provideFor($event) as $listener) {
            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logFailure($event, $listener, $e, false);
            }
        }
    }

    private function logFailure(
        EventInterface $event,
        EventListenerInterface $listener,
        \Throwable $exception,
        bool $critical,
    ): void {
        if ($this->logger === null) {
            return;
        }

        try {
            $this->logger->error(
                'Auth event listener failed',
                [
                    'event' => $event::class,
                    'listener' => $listener::class,
                    'critical' => $critical,
                    'exception' => $exception,
                ],
            );
        } catch (\Throwable) {
        }
    }
}
