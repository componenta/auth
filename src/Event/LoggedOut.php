<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

/** Generic logout event containing no reusable identity object or credential. */
final readonly class LoggedOut implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public UuidInterface $subjectId,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
