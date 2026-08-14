<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionsTerminated;

final readonly class RememberMeTerminationListener implements CriticalEventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    public function __construct(
        private RememberMeTokenManagerInterface $tokenManager,
    ) {
        $this->events = [SessionsTerminated::class, AllSessionsTerminated::class];
    }

    #[\Override]
    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void {
        if ($event instanceof SessionsTerminated) {
            $this->tokenManager->revokeForSessions($event->sessionIds);

            return;
        }

        if ($event instanceof AllSessionsTerminated) {
            $this->tokenManager->revokeAllForSubject(
                $event->subjectId,
                $event->exceptSessionId,
            );

            return;
        }

        throw new \InvalidArgumentException(sprintf(
            '%s cannot handle %s.',
            self::class,
            $event::class,
        ));
    }
}
