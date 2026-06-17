<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see SessionsTerminated} events.
 */
interface SessionsTerminatedListenerInterface extends EventListenerInterface
{
    /**
     * @param SessionsTerminated $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
