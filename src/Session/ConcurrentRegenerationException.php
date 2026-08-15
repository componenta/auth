<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * The optimistic claim on a session was lost to another regeneration.
 *
 * Callers must fail authentication for the presented session ID. They must not
 * follow the replacement row or disclose the winning successor credential.
 */
final class ConcurrentRegenerationException extends \RuntimeException
{
}
