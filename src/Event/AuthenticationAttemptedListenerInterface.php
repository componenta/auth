<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see AuthenticationAttempted} events.
 */
interface AuthenticationAttemptedListenerInterface extends EventListenerInterface
{
    /**
     * @param AuthenticationAttempted $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
