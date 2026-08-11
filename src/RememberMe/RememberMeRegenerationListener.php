<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionRegeneratedListenerInterface;

final readonly class RememberMeRegenerationListener implements
    SessionRegeneratedListenerInterface,
    CriticalEventListenerInterface
{
    public function __construct(private RememberMeTokenManagerInterface $tokenManager) {}

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
