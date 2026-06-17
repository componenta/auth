<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Refresh token has expired.
 *
 * The user must re-authenticate to obtain a new token pair.
 */
final class RefreshTokenExpired implements DeniedReasonInterface
{
    public string $code {
        get => 'refresh_token_expired';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
