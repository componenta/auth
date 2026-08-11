<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Wrong password or unknown identity.
 */
final class InvalidCredentials implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_credentials';
    }

    /** @param array<string, mixed> $attributes */
    public function __construct(
        public readonly array $attributes = []
    ) {
    }
}
