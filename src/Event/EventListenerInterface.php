<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerInterface
{
    public function handleEvent(EventInterface $event): void;
}
