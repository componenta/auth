<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Componenta\DI\LazyServiceFactoryInterface;
use Componenta\DI\ProxyFactoryInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseRememberMeTokenManagerConfigFactory implements LazyServiceFactoryInterface
{
    #[\Override]
    public function lazy(
        ContainerInterface $container,
        ProxyFactoryInterface $proxyFactory,
        array $context = [],
    ): object {
        return $proxyFactory->makeProxy(
            DatabaseRememberMeTokenManagerConfig::class,
            fn(object $proxy): DatabaseRememberMeTokenManagerConfig => $this->__invoke($container),
        );
    }

    public function __invoke(ContainerInterface $container): DatabaseRememberMeTokenManagerConfig
    {
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $prefix = ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME;

        return new DatabaseRememberMeTokenManagerConfig(
            table: $config->string(new ConfigPath($prefix . '.table'), 'remember_me_tokens'),
            dateFormat: $config->string(new ConfigPath($prefix . '.dateFormat'), 'Y-m-d H:i:s'),
            ttl: $config->int(new ConfigPath($prefix . '.ttl'), 2592000),
            idColumn: $config->string(new ConfigPath($prefix . '.columns.id'), 'id'),
            subjectIdColumn: $config->string(new ConfigPath($prefix . '.columns.subjectId'), 'user_id'),
            tokenColumn: $config->string(new ConfigPath($prefix . '.columns.token'), 'token'),
            sessionIdColumn: $config->string(new ConfigPath($prefix . '.columns.sessionId'), 'session_id'),
            expiresAtColumn: $config->string(new ConfigPath($prefix . '.columns.expiresAt'), 'expires_at'),
            createdAtColumn: $config->string(new ConfigPath($prefix . '.columns.createdAt'), 'created_at'),
        );
    }
}
