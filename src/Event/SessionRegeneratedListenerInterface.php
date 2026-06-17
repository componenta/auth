<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/**
 * Marker for listeners handling {@see SessionRegenerated} events.
 */
interface SessionRegeneratedListenerInterface extends EventListenerInterface
{
    /**
     * @param SessionRegenerated $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void;
}
