<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\PublicDeniedReasonInterface;

/** User account is disabled. Internal identifiers and notes are audit-only. */
final class UserDisabled implements PublicDeniedReasonInterface
{
    public string $code {
        get => 'user_disabled';
    }

    public function __construct(
        public readonly ?string $userId = null,
        public readonly ?string $reason = null,
    ) {}

    public array $attributes {
        get {
            return array_filter([
                'user_id' => $this->userId,
                'reason' => $this->reason,
            ], static fn(?string $value): bool => $value !== null);
        }
    }

    public function publicDetails(): array
    {
        return [];
    }
}
