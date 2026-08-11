<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class SessionRegenerated implements EventInterface, \JsonSerializable
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        #[\SensitiveParameter]
        public string $oldSessionId,
        #[\SensitiveParameter]
        public string $newSessionId,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }

    /** @return array{oldSessionId: string, newSessionId: string, timestamp: string} */
    public function __debugInfo(): array
    {
        return [
            'oldSessionId' => '[REDACTED]',
            'newSessionId' => '[REDACTED]',
            'timestamp' => $this->timestamp->format(DATE_ATOM),
        ];
    }

    /** @return array{oldSessionId: string, newSessionId: string, timestamp: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
