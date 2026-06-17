<?php

declare(strict_types=1);

namespace Componenta\Auth;

/**
 * A strategy for authenticating a specific type of payload.
 *
 * Each strategy handles one authentication mechanism (password, token, etc.)
 * and declares which payloads it supports via supports().
 */
interface AuthenticationStrategyInterface
{
    /**
     * Determines if this strategy supports the given payload.
     *
     * @param object $payload The payload to check
     * @return bool True if this strategy can authenticate the payload
     */
    public function supports(object $payload, ContextInterface $context): bool;

    /**
     * Authenticates the given payload.
     *
     * Must only be called after {@see supports()} returns true.
     * Behavior is undefined if called without a preceding supports() check.
     *
     * @param object $payload The authentication payload
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult;
}
