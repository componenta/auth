<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events { get; }

    public function handleEvent(EventInterface $event): void;
}
