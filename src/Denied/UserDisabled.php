<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * User account is disabled.
 */
final class UserDisabled implements DeniedReasonInterface
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
            ], static fn(?string $v) => $v !== null);
        }
    }
}
