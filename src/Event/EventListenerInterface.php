<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerInterface
{
    /**
     * Concrete event class names handled by this listener.
     * Subscriptions match the exact runtime class, without inheritance lookup.
     * Class aliases and equivalent PHP class names resolve to that same class.
     *
     * @var list<string>
     */
    public array $events { get; }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void;
}
