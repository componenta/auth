<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Session;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;

final readonly class SessionStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private SessionManagerInterface $sessionManager,
        private UserProviderInterface $provider,
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof SessionPayload && $payload->sessionId !== null;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var SessionPayload $payload */
        $session = $this->sessionManager->find($payload->sessionId);

        if ($session === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        $user = $this->provider->findById($session->userId);

        if ($user === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        $user->currentSessionId = $session->id;

        $transportPayload = $session->id !== $payload->sessionId
            ? new SessionPayload($session->id)
            : null;

        return new AuthenticationResult(
            subject: $user,
            transportPayload: $transportPayload,
            attributes: [SessionInterface::class => $session],
        );
    }
}
