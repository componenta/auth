<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

final class PriorityListenerProvider implements EventListenerProviderInterface
{
    /** @var array<int, list<EventListenerInterface>> */
    private array $listeners = [];
    private bool $sorted = false;

    public function addListener(
        #[\SensitiveParameter]
        EventListenerInterface $listener,
        int $priority = 0,
    ): void {
        self::assertEvents($listener);
        $this->listeners[$priority][] = $listener;
        $this->sorted = false;
    }

    #[\Override]
    public function provideFor(
        #[\SensitiveParameter]
        EventInterface $event,
    ): iterable {
        if (!$this->sorted) {
            krsort($this->listeners);
            $this->sorted = true;
        }

        foreach ($this->listeners as $listeners) {
            foreach ($listeners as $listener) {
                foreach ($listener->events as $eventType) {
                    if (
                        $eventType === $event::class
                        || (
                            class_exists($eventType)
                            && (new \ReflectionClass($eventType))->getName() === $event::class
                        )
                    ) {
                        yield $listener;
                        break;
                    }
                }
            }
        }
    }

    private static function assertEvents(
        #[\SensitiveParameter]
        EventListenerInterface $listener,
    ): void {
        $events = $listener->events;

        if ($events === []) {
            throw new \InvalidArgumentException(
                'An auth event listener must subscribe to at least one event.',
            );
        }

        foreach ($events as $event) {
            if (
                !class_exists($event)
                || !is_a($event, EventInterface::class, true)
                || (new \ReflectionClass($event))->isAbstract()
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'Auth event listener %s declares an invalid event type.',
                    $listener::class,
                ));
            }
        }
    }
}
