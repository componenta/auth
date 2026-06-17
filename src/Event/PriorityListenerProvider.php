<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

final class PriorityListenerProvider implements EventListenerProviderInterface
{
    /** @var array<int, list<EventListenerInterface>> */
    private array $listeners = [];
    private bool $sorted = false;

    public function addListener(
        EventListenerInterface $listener,
        int $priority = 0,
    ): void {
        $this->listeners[$priority][] = $listener;
        $this->sorted = false;
    }

    #[\Override]
    public function provideFor(EventInterface $event): iterable
    {
        if (!$this->sorted) {
            krsort($this->listeners);
            $this->sorted = true;
        }

        $interface = match ($event::class) {
            AuthenticationAttempted::class => AuthenticationAttemptedListenerInterface::class,
            AuthenticationSucceeded::class => AuthenticationSucceededListenerInterface::class,
            AuthenticationDenied::class => AuthenticationDeniedListenerInterface::class,
            LoggedOut::class => LoggedOutListenerInterface::class,
            SessionRegenerated::class => SessionRegeneratedListenerInterface::class,
            SessionsTerminated::class => SessionsTerminatedListenerInterface::class,
            AllSessionsTerminated::class => AllSessionsTerminatedListenerInterface::class,
            // Unknown event types (e.g. application-defined events dispatched
            // through the same provider) yield nothing instead of crashing
            // the dispatcher with UnhandledMatchError.
            default => null,
        };

        if ($interface === null) {
            return;
        }

        foreach ($this->listeners as $listeners) {
            foreach ($listeners as $listener) {
                if ($listener instanceof $interface) {
                    yield $listener;
                }
            }
        }
    }
}
