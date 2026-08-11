<?php

declare(strict_types=1);

namespace Componenta\Auth\Event;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Clock\Clock;
use DateTimeImmutable;

final readonly class AuthenticationDenied implements EventInterface, \JsonSerializable
{
    public DateTimeImmutable $timestamp;

    public function __construct(
        public DeniedReasonInterface $reason,
        public string $payloadType,
        ?DateTimeImmutable $timestamp = null,
    ) {
        $this->timestamp = $timestamp ?? new Clock()->now();
    }

    /** @return array{reasonType: string, code: string, payloadType: string, timestamp: string} */
    public function __debugInfo(): array
    {
        return [
            'reasonType' => $this->reason::class,
            'code' => $this->reason->code,
            'payloadType' => $this->payloadType,
            'timestamp' => $this->timestamp->format(DATE_ATOM),
        ];
    }

    /** @return array{reasonType: string, code: string, payloadType: string, timestamp: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
