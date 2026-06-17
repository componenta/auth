<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Too many failed verification attempts for this code.
 */
final class TooManyAttempts implements DeniedReasonInterface
{
    public string $code {
        get => 'too_many_attempts';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
