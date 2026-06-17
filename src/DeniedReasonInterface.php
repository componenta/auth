<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Represents a reason why authentication was denied.
 *
 * Implementations should be immutable and contain all relevant
 * information about the denial as public readonly properties.
 *
 */
interface DeniedReasonInterface
{
    /**
     * A machine-readable code identifying the denial reason.
     *
     * Examples: 'invalid_credentials', 'user_disabled', 'rate_limited'
     */
    public string $code { get; }

    /**
     * Returns additional data about the denial.
     *
     * Used for logging, serialization, and HTTP response formatting.
     * Should include all public properties as key-value pairs.
     *
     * @return array<string, mixed>
     */
    public array $attributes { get; }
}
