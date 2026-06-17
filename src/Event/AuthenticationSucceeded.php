<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use DateTimeImmutable;

final readonly class AuthenticationSucceeded implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public IdentityInterface $user,
        public object $payload,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }
}
