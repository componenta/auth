<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see AllSessionsTerminated} events.
 */
interface AllSessionsTerminatedListenerInterface extends EventListenerInterface
{
    /**
     * @param AllSessionsTerminated $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
