<?php

declare(strict_types=1);

namespace Componenta\Auth;

/** Represents a reason why authentication was denied. */
interface DeniedReasonInterface
{
    /** Machine-readable public error code. */
    public string $code { get; }

    /**
     * Trusted audit context. The default HTTP responder never serializes it;
     * custom client-facing denial payloads belong in a custom
     * DeniedResponseFactoryInterface implementation.
     *
     * @var array<string, mixed>
     */
    public array $attributes { get; }
}
