<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * OTP code has expired.
 */
final class CodeExpired implements DeniedReasonInterface
{
    public string $code {
        get => 'code_expired';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
