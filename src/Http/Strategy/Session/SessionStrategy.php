<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Session;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Clock\DateTimeFactoryInterface;

final readonly class SessionStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private SessionManagerInterface $sessionManager,
        private UserProviderInterface $provider,
        private DateTimeFactoryInterface $dateTimeFactory,
    ) {}

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof SessionPayload && $payload->sessionId !== null;
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var SessionPayload $payload */
        $sessionId = $payload->sessionId;

        if ($sessionId === null) {
            return $this->denied($payload);
        }

        $session = $this->sessionManager->find($sessionId);

        if ($session === null || $session->id !== $sessionId) {
            return $this->denied($payload);
        }

        $identity = $this->provider->findByUuid($session->subjectId);

        if (
            $identity === null
            || !$session->subjectId->equals($identity->uuid)
        ) {
            return $this->denied($payload);
        }

        $transportPayload = null;

        if ($session->regenerateAt <= $this->dateTimeFactory->now()) {
            try {
                $regenerated = $this->sessionManager->regenerate($sessionId);
            } catch (ConcurrentRegenerationException|\InvalidArgumentException) {
                return $this->denied($payload);
            }

            if (!$regenerated->subjectId->equals($identity->uuid)) {
                throw new \UnexpectedValueException(
                    'Regenerated session does not belong to the authenticated identity.',
                );
            }

            $session = $regenerated;
            $transportPayload = new SessionPayload($session->id);
            $transportState = $context->getAttribute(CredentialTransportState::class);

            if ($transportState instanceof CredentialTransportState) {
                $regeneratedId = $session->id;
                $transportState->onDiscard(
                    fn() => $this->sessionManager->terminate($regeneratedId),
                );
            }
        }

        return new AuthenticationResult(
            subject: $identity,
            transportPayload: $transportPayload,
            session: $session,
        );
    }

    private function denied(SessionPayload $payload): AuthenticationResult
    {
        return new AuthenticationResult(
            subject: new InvalidCredentials(),
            continueOnFailure: $payload->rememberMeToken !== null,
        );
    }
}
