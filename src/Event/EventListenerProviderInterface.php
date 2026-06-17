<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

interface EventListenerProviderInterface
{
    /**
     * @return iterable<EventListenerInterface>
     */
    public function provideFor(EventInterface $event): iterable;
}
