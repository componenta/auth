<?php

declare(strict_types=1);

namespace Componenta\Auth;

/** Explicit opt-in for denial details safe to expose to an unauthenticated client. */
interface PublicDeniedReasonInterface extends DeniedReasonInterface
{
    /** @var array<string, scalar|null> */
    public array $publicDetails { get; }
}
