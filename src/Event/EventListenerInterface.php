<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerInterface
{
    /**
     * Concrete event class names handled by this listener.
     * Subscriptions match the exact runtime class, without inheritance lookup.
     *
     * @var list<string>
     */
    public array $events { get; }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void;
}
