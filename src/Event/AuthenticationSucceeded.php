<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

/** Generic audit event containing only a canonical identity identifier. */
final readonly class AuthenticationSucceeded implements EventInterface
{
    public function __construct(
        public UuidInterface $subjectId,
        public string $payloadType,
        public DateTimeImmutable $timestamp,
    ) {}
}
