<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Refresh token is not found or is invalid.
 */
final class InvalidRefreshToken implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_refresh_token';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
