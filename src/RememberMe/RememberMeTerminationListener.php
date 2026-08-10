<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\AllSessionsTerminatedListenerInterface;
use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Auth\Event\SessionsTerminatedListenerInterface;

final readonly class RememberMeTerminationListener implements
    SessionsTerminatedListenerInterface,
    AllSessionsTerminatedListenerInterface,
    CriticalEventListenerInterface
{
    public function __construct(private RememberMeTokenManagerInterface $tokenManager) {}

    #[\Override]
    public function handleEvent(EventInterface $event): void
    {
        match ($event::class) {
            SessionsTerminated::class => $this->tokenManager->revokeForSessions($event->sessionIds),
            AllSessionsTerminated::class => $this->tokenManager->revokeAllForUser(
                $event->userId,
                $event->exceptSessionId,
            ),
        };
    }
}
