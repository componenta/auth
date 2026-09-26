<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerInterface
{
    /**
     * Event class names handled by this listener.
     *
     * @var list<string>
     */
    public array $events { get; }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void;
}
