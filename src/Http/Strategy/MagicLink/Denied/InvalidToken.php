<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Token signature is invalid or token is malformed.
 */
final class InvalidToken implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_token';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
