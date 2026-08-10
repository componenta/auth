<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

/** Marker for synchronous security participants whose failure must surface. */
interface CriticalEventListenerInterface extends EventListenerInterface
{
}
