<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class AuthenticationAttempted implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public object $payload,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}