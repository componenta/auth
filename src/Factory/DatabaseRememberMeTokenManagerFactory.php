<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\DI\LazyServiceFactoryInterface;
use Componenta\DI\ProxyFactoryInterface;
use Cycle\Database\DatabaseInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseRememberMeTokenManagerFactory implements LazyServiceFactoryInterface
{
    public function __invoke(ContainerInterface $container): DatabaseRememberMeTokenManager
    {
        return new DatabaseRememberMeTokenManager(
            database: $container->get(DatabaseInterface::class),
            dateTimeFactory: $container->get(DateTimeFactoryInterface::class),
            config: $container->get(DatabaseRememberMeTokenManagerConfig::class),
        );
    }

    public function lazy(ContainerInterface $container, ProxyFactoryInterface $proxyFactory, array $context = []): object
    {
        return $proxyFactory->makeLazy(
            DatabaseRememberMeTokenManager::class,
            fn(object $instance) => $instance->__construct(
                database: $container->get(DatabaseInterface::class),
                dateTimeFactory: $container->get(DateTimeFactoryInterface::class),
                config: $container->get(DatabaseRememberMeTokenManagerConfig::class),
            ),
        );
    }
}
