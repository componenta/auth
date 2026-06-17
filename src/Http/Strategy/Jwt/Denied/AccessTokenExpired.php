<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Access token has expired.
 *
 * The client should use the refresh token to obtain
 * a new access token.
 */
final class AccessTokenExpired implements DeniedReasonInterface
{
    public string $code {
        get => 'access_token_expired';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
