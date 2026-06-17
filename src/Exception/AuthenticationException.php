<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

/**
 * Base exception for all authentication errors.
 *
 * This exception indicates infrastructure or configuration errors,
 * not authentication failures (which are represented by DeniedReasonInterface).
 */
class AuthenticationException extends \RuntimeException implements AuthenticationExceptionInterface
{
}
