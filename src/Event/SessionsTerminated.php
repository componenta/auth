<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class SessionsTerminated implements EventInterface
{
    public DateTimeImmutable $timestamp;

    /**
     * @param string[] $sessionIds
     */
    public function __construct(
        public array $sessionIds,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
