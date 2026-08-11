<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

/** Generic audit event containing only a canonical identity identifier. */
final readonly class AuthenticationSucceeded implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public UuidInterface $subjectId,
        public string $payloadType,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
