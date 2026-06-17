<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Token signature is valid but TTL has expired.
 */
final class TokenExpired implements DeniedReasonInterface
{
    public string $code {
        get => 'token_expired';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
