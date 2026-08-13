<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\RememberMe;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionManagerInterface;

/**
 * Adds response-discard compensation to a remember-me strategy.
 *
 * Use this wrapper when a strategy runs through AuthenticationMiddleware so a
 * successor grant/session that cannot be published to the client is revoked.
 */
final readonly class CompensatingRememberMeStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private AuthenticationStrategyInterface $strategy,
        private RememberMeTokenManagerInterface $tokenManager,
        private SessionManagerInterface $sessionManager,
    ) {}

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $this->strategy->supports($payload, $context);
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $result = $this->strategy->attempt($payload, $context);
        $transportPayload = $result->transportPayload;
        $session = $result->session;
        $state = $context->getAttribute(CredentialTransportState::class);

        if (
            !$transportPayload instanceof SessionPayload
            || $transportPayload->rememberMeToken === null
            || $session === null
            || !$state instanceof CredentialTransportState
        ) {
            return $result;
        }

        $successorToken = $transportPayload->rememberMeToken;
        $state->onDiscard(function () use ($successorToken, $session): void {
            try {
                $this->tokenManager->revoke($successorToken);
            } finally {
                $this->sessionManager->terminate($session->id);
            }
        });

        return $result;
    }
}
