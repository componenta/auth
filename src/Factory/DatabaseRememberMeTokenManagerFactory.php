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
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DatabaseRememberMeTokenManager {
        return new DatabaseRememberMeTokenManager(
            database: self::database($container),
            dateTimeFactory: self::dateTimeFactory($container),
            config: self::config($container),
        );
    }

    #[\Override]
    public function lazy(
        #[\SensitiveParameter]
        ContainerInterface $container,
        ProxyFactoryInterface $proxyFactory,
        array $context = [],
    ): object {
        return $proxyFactory->makeLazy(
            DatabaseRememberMeTokenManager::class,
            static function (object $instance) use ($container): void {
                if (!$instance instanceof DatabaseRememberMeTokenManager) {
                    throw new \LogicException(sprintf(
                        'Lazy instance must be %s.',
                        DatabaseRememberMeTokenManager::class,
                    ));
                }

                $instance->__construct(
                    database: self::database($container),
                    dateTimeFactory: self::dateTimeFactory($container),
                    config: self::config($container),
                );
            },
        );
    }

    private static function database(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DatabaseInterface {
        $service = $container->get(DatabaseInterface::class);

        return $service instanceof DatabaseInterface
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', DatabaseInterface::class, DatabaseInterface::class));
    }

    private static function dateTimeFactory(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DateTimeFactoryInterface {
        $service = $container->get(DateTimeFactoryInterface::class);

        return $service instanceof DateTimeFactoryInterface
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', DateTimeFactoryInterface::class, DateTimeFactoryInterface::class));
    }

    private static function config(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DatabaseRememberMeTokenManagerConfig {
        $service = $container->get(DatabaseRememberMeTokenManagerConfig::class);

        return $service instanceof DatabaseRememberMeTokenManagerConfig
            ? $service
            : throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseRememberMeTokenManagerConfig::class,
                DatabaseRememberMeTokenManagerConfig::class,
            ));
    }
}
