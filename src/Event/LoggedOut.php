<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

/** Generic logout event containing no reusable identity object or credential. */
final readonly class LoggedOut implements EventInterface
{
    public function __construct(
        public UuidInterface $subjectId,
        public DateTimeImmutable $timestamp,
    ) {}
}
