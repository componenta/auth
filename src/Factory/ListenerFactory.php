<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\AllSessionsTerminatedListenerInterface;
use Componenta\Auth\Event\AuthenticationAttempted;
use Componenta\Auth\Event\AuthenticationAttemptedListenerInterface;
use Componenta\Auth\Event\AuthenticationDenied;
use Componenta\Auth\Event\AuthenticationDeniedListenerInterface;
use Componenta\Auth\Event\AuthenticationSucceeded;
use Componenta\Auth\Event\AuthenticationSucceededListenerInterface;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\LoggedOut;
use Componenta\Auth\Event\LoggedOutListenerInterface;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionRegeneratedListenerInterface;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Auth\Event\SessionsTerminatedListenerInterface;

final class ListenerFactory
{
    /**
     * @param callable(AuthenticationAttempted): void $callback
     */
    public static function onAttempted(callable $callback): AuthenticationAttemptedListenerInterface
    {
        return new readonly class($callback) implements AuthenticationAttemptedListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(AuthenticationSucceeded): void $callback
     */
    public static function onSucceeded(callable $callback): AuthenticationSucceededListenerInterface
    {
        return new readonly class($callback) implements AuthenticationSucceededListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(AuthenticationDenied): void $callback
     */
    public static function onDenied(callable $callback): AuthenticationDeniedListenerInterface
    {
        return new readonly class($callback) implements AuthenticationDeniedListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(LoggedOut): void $callback
     */
    public static function onLoggedOut(callable $callback): LoggedOutListenerInterface
    {
        return new readonly class($callback) implements LoggedOutListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(SessionRegenerated): void $callback
     */
    public static function onSessionRegenerated(callable $callback): SessionRegeneratedListenerInterface
    {
        return new readonly class($callback) implements SessionRegeneratedListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(SessionsTerminated): void $callback
     */
    public static function onSessionsTerminated(callable $callback): SessionsTerminatedListenerInterface
    {
        return new readonly class($callback) implements SessionsTerminatedListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }

    /**
     * @param callable(AllSessionsTerminated): void $callback
     */
    public static function onAllSessionsTerminated(callable $callback): AllSessionsTerminatedListenerInterface
    {
        return new readonly class($callback) implements AllSessionsTerminatedListenerInterface {
            public function __construct(
                private mixed $callback,
            ) {}

            #[\Override]
            public function handleEvent(EventInterface $event): void
            {
                ($this->callback)($event);
            }
        };
    }
}
