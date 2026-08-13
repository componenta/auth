<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\ContextInterface;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;

/** Registers cleanup for a rotated remember credential that has not reached the client yet. */
final class RememberMeDiscardCompensation
{
    private function __construct() {}

    public static function register(
        ContextInterface $context,
        RememberMeRotation $rotation,
        SessionInterface $session,
        RememberMeTokenManagerInterface $tokenManager,
        SessionManagerInterface $sessionManager,
    ): void {
        $state = $context->getAttribute(CredentialTransportState::class);
        if (!$state instanceof CredentialTransportState) {
            return;
        }

        $state->onDiscard(static function () use (
            $rotation,
            $session,
            $tokenManager,
            $sessionManager,
        ): void {
            try {
                $tokenManager->revoke($rotation->successorToken);
            } finally {
                $sessionManager->terminate($session->id);
            }
        });
    }
}
