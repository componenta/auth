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
            database: self::database($container),
            idGenerator: self::idGenerator($container),
            dateTimeFactory: self::dateTimeFactory($container),
            dispatcher: self::dispatcher($container),
            config: self::config($container),
        );
    }

    #[\Override]
    public function lazy(
        ContainerInterface $container,
        ProxyFactoryInterface $proxyFactory,
        array $context = [],
    ): object {
        return $proxyFactory->makeLazy(
            DatabaseSessionManager::class,
            static function (object $instance) use ($container): void {
                if (!$instance instanceof DatabaseSessionManager) {
                    throw new \LogicException(sprintf(
                        'Lazy instance must be %s.',
                        DatabaseSessionManager::class,
                    ));
                }

                $instance->__construct(
                    database: self::database($container),
                    idGenerator: self::idGenerator($container),
                    dateTimeFactory: self::dateTimeFactory($container),
                    dispatcher: self::dispatcher($container),
                    config: self::config($container),
                );
            },
        );
    }

    private static function database(ContainerInterface $container): DatabaseInterface
    {
        $service = $container->get(DatabaseInterface::class);

        return $service instanceof DatabaseInterface
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', DatabaseInterface::class, DatabaseInterface::class));
    }

    private static function idGenerator(ContainerInterface $container): SessionIdGeneratorInterface
    {
        $service = $container->get(SessionIdGeneratorInterface::class);

        return $service instanceof SessionIdGeneratorInterface
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', SessionIdGeneratorInterface::class, SessionIdGeneratorInterface::class));
    }

    private static function dateTimeFactory(ContainerInterface $container): DateTimeFactoryInterface
    {
        $service = $container->get(DateTimeFactoryInterface::class);

        return $service instanceof DateTimeFactoryInterface
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', DateTimeFactoryInterface::class, DateTimeFactoryInterface::class));
    }

    private static function dispatcher(ContainerInterface $container): EventDispatcher
    {
        $service = $container->get(EventDispatcher::class);

        return $service instanceof EventDispatcher
            ? $service
            : throw new \LogicException(sprintf('%s must resolve to %s.', EventDispatcher::class, EventDispatcher::class));
    }

    private static function config(ContainerInterface $container): DatabaseSessionManagerConfig
    {
        $service = $container->get(DatabaseSessionManagerConfig::class);

        return $service instanceof DatabaseSessionManagerConfig
            ? $service
            : throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseSessionManagerConfig::class,
                DatabaseSessionManagerConfig::class,
            ));
    }
}
