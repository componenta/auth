<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class AuthenticationDenied implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public DeniedReasonInterface $reason,
        public object $payload,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}