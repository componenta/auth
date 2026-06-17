<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class AllSessionsTerminated implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public int|string $userId,
        public ?string $exceptSessionId = null,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
