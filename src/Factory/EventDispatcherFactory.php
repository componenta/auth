<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final readonly class EventDispatcherFactory
{
    public function __invoke(ContainerInterface $container): EventDispatcher
    {
        return new EventDispatcher(
            provider: $container->get(EventListenerProviderInterface::class),
            logger: $container->has(LoggerInterface::class)
                ? $container->get(LoggerInterface::class)
                : null,
        );
    }
}
