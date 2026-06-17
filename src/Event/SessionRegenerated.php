<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class SessionRegenerated implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public string $oldSessionId,
        public string $newSessionId,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
