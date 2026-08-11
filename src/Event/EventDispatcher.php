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
     * Executes only security-critical participants and surfaces the first
     * failure after giving every critical participant a chance to run.
     */
    public function dispatchCritical(EventInterface $event): void
    {
        $criticalFailure = null;

        foreach ($this->provider->provideFor($event) as $listener) {
            if (!$listener instanceof CriticalEventListenerInterface) {
                continue;
            }

            try {
                $listener->handleEvent($event);
            } catch (\Throwable $e) {
                $this->logFailure($event, $listener, $e, true);
                $criticalFailure ??= $e;
            }
        }

        if ($criticalFailure instanceof \Throwable) {
            throw $criticalFailure;
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
