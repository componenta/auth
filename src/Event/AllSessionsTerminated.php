<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Clock\Clock;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class AllSessionsTerminated implements EventInterface, \JsonSerializable
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
        public ?string $exceptSessionId = null,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }

    /** @return array{subjectId: string, exceptSessionId: string|null, timestamp: string} */
    public function __debugInfo(): array
    {
        return [
            'subjectId' => $this->subjectId->toString(),
            'exceptSessionId' => $this->exceptSessionId === null
                ? null
                : '[REDACTED]',
            'timestamp' => $this->timestamp->format(DATE_ATOM),
        ];
    }

    /** @return array{subjectId: string, exceptSessionId: string|null, timestamp: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
