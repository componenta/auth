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

    public function handleEvent(EventInterface $event): void
    {
        /** @var SessionRegenerated $event */
        $this->tokenManager->updateSessionId($event->oldSessionId, $event->newSessionId);
    }
}
