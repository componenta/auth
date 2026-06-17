<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

/**
 * Thrown when a transport operation fails.
 *
 * This indicates errors during payload storage or removal.
 */
class TransportException extends AuthenticationException
{
}
