<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Identity\UuidInterface;

/** Disabled account denial; subject identity and notes remain audit-only. */
final class UserDisabled implements DeniedReasonInterface, \JsonSerializable
{
    public string $code {
        get => 'user_disabled';
    }

    public function __construct(
        public readonly ?UuidInterface $subjectId = null,
        public readonly ?string $reason = null,
    ) {}

    /** @var array<string, mixed> */
    public array $attributes {
        get {
            return array_filter([
                'subject_id' => $this->subjectId?->toString(),
                'reason' => $this->reason,
            ], static fn(?string $value): bool => $value !== null);
        }
    }

    /** @return array{code: string} */
    public function __debugInfo(): array
    {
        return ['code' => $this->code];
    }

    /** @return array{code: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
