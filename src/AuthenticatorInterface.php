<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Exception\AuthenticationExceptionInterface;

/**
 * Authenticates a payload using registered strategies.
 *
 * This is the main entry point for authentication. It delegates
 * to AuthenticationStrategyInterface implementations to perform
 * the actual authentication.
 */
interface AuthenticatorInterface
{
    /**
     * Attempts to authenticate the given payload.
     *
     * @param object $payload The authentication payload
     *
     * @throws AuthenticationExceptionInterface
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult;
}
