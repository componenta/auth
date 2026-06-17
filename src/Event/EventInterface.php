<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use DateTimeImmutable;

interface EventInterface
{
    public DateTimeImmutable $timestamp { get; }
}
