<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionRegeneratedListenerInterface;

/**
 * Updates remember-me token session binding when a session is regenerated.
 *
 * Keeps the token pointing to the current (leaf) session so that
 * terminateAll(except: currentSession) preserves the token correctly.
 */
final readonly class RememberMeRegenerationListener implements SessionRegeneratedListenerInterface
{
    public function __construct(
        private RememberMeTokenManagerInterface $tokenManager,
    ) {}

    /**
     * @param SessionRegenerated $event
     * @return void
     */
    public function handleEvent(EventInterface $event): void
    {
        $this->tokenManager->updateSessionId($event->oldSessionId, $event->newSessionId);
    }
}
