<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use DateTimeImmutable;

final readonly class LoggedOut implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public IdentityInterface $user,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
