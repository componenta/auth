<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

/**
 * Thrown when the user provider encounters an error.
 *
 * This indicates infrastructure errors (database connection, etc.),
 * not "user not found" which is represented by returning null.
 */
class UserProviderException extends AuthenticationException
{
}
