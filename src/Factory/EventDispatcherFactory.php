<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final readonly class EventDispatcherFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): EventDispatcher {
        $provider = $container->get(EventListenerProviderInterface::class);

        if (!$provider instanceof EventListenerProviderInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                EventListenerProviderInterface::class,
                EventListenerProviderInterface::class,
            ));
        }

        $logger = null;

        if ($container->has(LoggerInterface::class)) {
            $logger = $container->get(LoggerInterface::class);

            if (!$logger instanceof LoggerInterface) {
                throw new \LogicException(sprintf(
                    '%s must resolve to %s.',
                    LoggerInterface::class,
                    LoggerInterface::class,
                ));
            }
        }

        return new EventDispatcher($provider, $logger);
    }
}
