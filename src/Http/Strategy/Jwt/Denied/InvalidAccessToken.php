<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Access token is malformed, has an invalid signature,
 * or the user no longer exists.
 */
final class InvalidAccessToken implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_access_token';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
