<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Token has already been used (one-time use enforced).
 */
final class TokenAlreadyUsed implements DeniedReasonInterface
{
    public string $code {
        get => 'token_already_used';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
