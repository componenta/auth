<?php

declare(strict_types=1);

namespace Componenta\Auth;

/** Represents a reason why authentication was denied. */
interface DeniedReasonInterface
{
    /** Machine-readable public error code. */
    public string $code { get; }

    /**
     * Trusted audit context. The default HTTP responder never serializes it.
     * Implement PublicDeniedReasonInterface to opt specific values into a
     * public response.
     *
     * @return array<string, mixed>
     */
    public array $attributes { get; }
}
