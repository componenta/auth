<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see AuthenticationDenied} events.
 */
interface AuthenticationDeniedListenerInterface extends EventListenerInterface
{
    /**
     * @param AuthenticationDenied $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
