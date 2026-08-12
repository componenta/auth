<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionRegenerated;

final readonly class RememberMeRegenerationListener implements CriticalEventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    public function __construct(private RememberMeTokenManagerInterface $tokenManager)
    {
        $this->events = [SessionRegenerated::class];
    }

    #[\Override]
    public function handleEvent(EventInterface $event): void
    {
        if (!$event instanceof SessionRegenerated) {
            throw new \InvalidArgumentException(sprintf(
                '%s cannot handle %s.',
                self::class,
                $event::class,
            ));
        }

        $this->tokenManager->updateSessionId($event->oldSessionId, $event->newSessionId);
    }
}
