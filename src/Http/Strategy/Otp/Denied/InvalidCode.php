<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * OTP code is invalid or does not match.
 */
final class InvalidCode implements DeniedReasonInterface
{
    public string $code {
        get => 'invalid_code';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
