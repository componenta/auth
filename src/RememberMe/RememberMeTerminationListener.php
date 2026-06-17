<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\AllSessionsTerminatedListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Auth\Event\SessionsTerminatedListenerInterface;

/**
 * Revokes remember-me tokens when sessions are terminated.
 */
final readonly class RememberMeTerminationListener implements SessionsTerminatedListenerInterface, AllSessionsTerminatedListenerInterface
{
    public function __construct(
        private RememberMeTokenManagerInterface $tokenManager,
    ) {}

    #[\Override]
    public function handleEvent(EventInterface $event): void
    {
        match ($event::class) {
            SessionsTerminated::class => $this->onSessionsTerminated($event),
            AllSessionsTerminated::class => $this->onAllSessionsTerminated($event),
        };
    }

    private function onSessionsTerminated(SessionsTerminated $event): void
    {
        foreach ($event->sessionIds as $sessionId) {
            $this->tokenManager->revokeForSession($sessionId);
        }
    }

    private function onAllSessionsTerminated(AllSessionsTerminated $event): void
    {
        $this->tokenManager->revokeAllForUser($event->userId, $event->exceptSessionId);
    }
}
