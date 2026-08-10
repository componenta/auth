<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Explicit opt-in for denial metadata that is safe to expose to an
 * unauthenticated HTTP client. DeniedReasonInterface::attributes remains
 * trusted audit context and is never serialized by the default responder.
 */
interface PublicDeniedReasonInterface extends DeniedReasonInterface
{
    /** @return array<string, scalar|null> */
    public function publicDetails(): array;
}
