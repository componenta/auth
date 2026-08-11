<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Componenta\DI\LazyServiceFactoryInterface;
use Componenta\DI\ProxyFactoryInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseSessionManagerConfigFactory implements LazyServiceFactoryInterface
{
    #[\Override]
    public function lazy(
        ContainerInterface $container,
        ProxyFactoryInterface $proxyFactory,
        array $context = [],
    ): object {
        return $proxyFactory->makeProxy(
            DatabaseSessionManagerConfig::class,
            fn(object $proxy): DatabaseSessionManagerConfig => $this->__invoke($container),
        );
    }

    public function __invoke(ContainerInterface $container): DatabaseSessionManagerConfig
    {
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $prefix = ConfigKey::AUTH . '.' . ConfigKey::SESSION;

        return new DatabaseSessionManagerConfig(
            table: $config->string(new ConfigPath($prefix . '.table'), 'sessions'),
            dateFormat: $config->string(new ConfigPath($prefix . '.dateFormat'), 'Y-m-d H:i:s'),
            lazyLoad: $config->bool(new ConfigPath($prefix . '.lazyLoad'), true),
            idleTimeout: $config->int(new ConfigPath($prefix . '.idleTimeout'), 1800),
            absoluteTimeout: $config->int(new ConfigPath($prefix . '.absoluteTimeout'), 28800),
            regenerationInterval: $config->int(new ConfigPath($prefix . '.regenerationInterval'), 300),
            regenerationGracePeriod: $config->int(new ConfigPath($prefix . '.regenerationGracePeriod'), 30),
            touchInterval: $config->int(new ConfigPath($prefix . '.touchInterval'), 60),
            idColumn: $config->string(new ConfigPath($prefix . '.columns.id'), 'id'),
            subjectIdColumn: $config->string(new ConfigPath($prefix . '.columns.subjectId'), 'user_id'),
            ipColumn: $config->string(new ConfigPath($prefix . '.columns.ip'), 'ip'),
            userAgentColumn: $config->string(new ConfigPath($prefix . '.columns.userAgent'), 'user_agent'),
            expiresAtColumn: $config->string(new ConfigPath($prefix . '.columns.expiresAt'), 'expires_at'),
            absoluteExpiresAtColumn: $config->string(new ConfigPath($prefix . '.columns.absoluteExpiresAt'), 'absolute_expires_at'),
            regenerateAtColumn: $config->string(new ConfigPath($prefix . '.columns.regenerateAt'), 'regenerate_at'),
            replacedByColumn: $config->string(new ConfigPath($prefix . '.columns.replacedBy'), 'replaced_by'),
            createdAtColumn: $config->string(new ConfigPath($prefix . '.columns.createdAt'), 'created_at'),
            lastActiveAtColumn: $config->string(new ConfigPath($prefix . '.columns.lastActiveAt'), 'last_active_at'),
            attributesColumn: $config->string(new ConfigPath($prefix . '.columns.attributes'), 'attributes'),
        );
    }
}
