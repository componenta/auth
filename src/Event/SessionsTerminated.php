<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use DateTimeImmutable;

final readonly class SessionsTerminated implements EventInterface, \JsonSerializable
{
    /** @param string[] $sessionIds */
    public function __construct(
        #[\SensitiveParameter]
        public array $sessionIds,
        public DateTimeImmutable $timestamp,
    ) {}

    /** @return array{sessionIds: list<string>, timestamp: string} */
    public function __debugInfo(): array
    {
        return [
            'sessionIds' => array_fill(0, count($this->sessionIds), '[REDACTED]'),
            'timestamp' => $this->timestamp->format(DATE_ATOM),
        ];
    }

    /** @return array{sessionIds: list<string>, timestamp: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
