<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGeneratorInterface;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\DI\LazyServiceFactoryInterface;
use Componenta\DI\ProxyFactoryInterface;
use Cycle\Database\DatabaseInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseSessionManagerFactory implements LazyServiceFactoryInterface
{
    public function __invoke(ContainerInterface $container): DatabaseSessionManager
    {
        return new DatabaseSessionManager(
            database: $container->get(DatabaseInterface::class),
            idGenerator: $container->get(SessionIdGeneratorInterface::class),
            dateTimeFactory: $container->get(DateTimeFactoryInterface::class),
            dispatcher: $container->get(EventDispatcher::class),
            config: $container->get(DatabaseSessionManagerConfig::class),
        );
    }

    public function lazy(ContainerInterface $container, ProxyFactoryInterface $proxyFactory): object
    {
        return $proxyFactory->makeLazy(
            DatabaseSessionManager::class,
            fn(object $instance) => $instance->__construct(
                database: $container->get(DatabaseInterface::class),
                idGenerator: $container->get(SessionIdGeneratorInterface::class),
                dateTimeFactory: $container->get(DateTimeFactoryInterface::class),
                dispatcher: $container->get(EventDispatcher::class),
                config: $container->get(DatabaseSessionManagerConfig::class),
            ),
        );
    }
}
