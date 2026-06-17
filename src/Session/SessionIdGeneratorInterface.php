<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

interface SessionIdGeneratorInterface
{
    /**
     * Generates a unique session identifier.
     *
     * The identifier must be collision-resistant and should be
     * cryptographically secure to prevent session prediction attacks.
     */
    public function generate(): string;
}