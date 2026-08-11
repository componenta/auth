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

    /**
     * Runs security-critical participants first. Best-effort observers only see
     * the event after every critical participant has completed successfully.
     */
    public function dispatch(EventInterface $event): void
    {
        $this->dispatchCritical($event);
        $this->dispatchBestEffort($event);
    }

    /**
     * Executes security-critical participants in provider order and stops on
     * the first failure. Continuing after a failed critical participant could
     * create irreversible side effects even though the owning transition is
     * going to fail or roll back.
     */
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

    /**
     * Executes only non-critical observers. Their failures are logged and
     * isolated from an already committed security transition.
     */
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

    /**
     * Executes every listener as an isolated observer.
     *
     * Use this only for post-transition audit/notification events where there
     * is no owning transaction left to roll back. A listener carrying the
     * critical marker is intentionally not allowed to turn such an observer
     * notification into a second security commit point.
     */
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
        $this->logger?->error(
            'Auth event listener failed',
            [
                'event' => $event::class,
                'listener' => $listener::class,
                'critical' => $critical,
                'exception' => $exception,
            ],
        );
    }
}
