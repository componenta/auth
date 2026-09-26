<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * Marker for non-secret request-local state established by authentication.
 *
 * The core carries at most one state object. Concrete capability packages own
 * the state type; Auth 3 core does not inspect or persist it.
 */
interface AuthenticationStateInterface
{
}
