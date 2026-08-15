<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * No authentication payload was provided.
 */
final class Unauthorized implements DeniedReasonInterface
{
    public string $code {
        get => 'unauthorized';
    }

    /** @param array<string, mixed> $attributes */
    public function __construct(
        public readonly array $attributes = []
    ) {
    }
}
