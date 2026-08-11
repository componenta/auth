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

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $payloadType = $payload::class;
        $this->dispatcher->dispatchObservers(new AuthenticationAttempted(
            $payloadType,
            $this->clock->now(),
        ));

        $result = $this->authenticator->attempt($payload, $context);

        if ($result->subject instanceof IdentityInterface) {
            $this->dispatcher->dispatchObservers(new AuthenticationSucceeded(
                $result->subject->uuid,
                $payloadType,
                $this->clock->now(),
            ));
        } else {
            $this->dispatcher->dispatchObservers(new AuthenticationDenied(
                $result->subject,
                $payloadType,
                $this->clock->now(),
            ));
        }

        return $result;
    }
}
