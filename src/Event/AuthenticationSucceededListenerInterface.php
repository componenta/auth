<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see AuthenticationSucceeded} events.
 */
interface AuthenticationSucceededListenerInterface extends EventListenerInterface
{
    /**
     * @param AuthenticationSucceeded $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
