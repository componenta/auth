<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Event\AuthenticationAttempted;
use Componenta\Auth\Event\AuthenticationDenied;
use Componenta\Auth\Event\AuthenticationSucceeded;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;

final readonly class EventingAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private AuthenticatorInterface $authenticator,
        private EventDispatcher $dispatcher,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $this->dispatcher->dispatch(new AuthenticationAttempted($payload, $this->clock->now()));

        $result = $this->authenticator->attempt($payload, $context);

        if ($result->subject instanceof IdentityInterface) {
            $this->dispatcher->dispatch(new AuthenticationSucceeded($result->subject, $payload, $this->clock->now()));
        } else {
            $this->dispatcher->dispatch(new AuthenticationDenied($result->subject, $payload, $this->clock->now()));
        }

        return $result;
    }
}
