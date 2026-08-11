<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Generic denial reason with custom code and attributes.
 */
final readonly class DeniedReason implements DeniedReasonInterface
{
    /** @param array<string, mixed> $attributes */
    public function __construct(
        public string $code,
        public array $attributes = [],
    ) {}
}