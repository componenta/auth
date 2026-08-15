<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use DateTimeImmutable;

/** Generic audit event deliberately containing no credential payload. */
final readonly class AuthenticationAttempted implements EventInterface
{
    public function __construct(
        public string $payloadType,
        public DateTimeImmutable $timestamp,
    ) {}
}
