<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see LoggedOut} events.
 */
interface LoggedOutListenerInterface extends EventListenerInterface
{
    /**
     * @param LoggedOut $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
