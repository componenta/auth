<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/** Queues bounded session cleanup outside the current HTTP request. */
interface SessionCleanupSchedulerInterface
{
    public function schedule(): void;
}
