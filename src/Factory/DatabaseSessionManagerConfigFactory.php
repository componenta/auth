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
    public function lazy(ContainerInterface $container, ProxyFactoryInterface $proxyFactory): object
    {
        return $proxyFactory->makeProxy(
            DatabaseSessionManagerConfig::class,
            fn(object $proxy): DatabaseSessionManagerConfig => $this->__invoke($container),
        );
    }

    public function __invoke(ContainerInterface $container): DatabaseSessionManagerConfig
    {
        /**
         * @var Config $config
         */
        $config = $container->get('config');
        $config = $config->array(new ConfigPath(ConfigKey::AUTH . '.' . ConfigKey::SESSION), []);

        return new DatabaseSessionManagerConfig(
            table: $config['table'] ?? 'sessions',
            dateFormat: $config['dateFormat'] ?? 'Y-m-d H:i:s',
            lazyLoad: $config['lazyLoad'] ?? true,
            idleTimeout: $config['idleTimeout'] ?? 1800,
            absoluteTimeout: $config['absoluteTimeout'] ?? 28800,
            regenerationInterval: $config['regenerationInterval'] ?? 300,
            regenerationGracePeriod: $config['regenerationGracePeriod'] ?? 30,
            idColumn: $config['columns']['id'] ?? 'id',
            userIdColumn: $config['columns']['userId'] ?? 'user_id',
            ipColumn: $config['columns']['ip'] ?? 'ip',
            userAgentColumn: $config['columns']['userAgent'] ?? 'user_agent',
            expiresAtColumn: $config['columns']['expiresAt'] ?? 'expires_at',
            absoluteExpiresAtColumn: $config['columns']['absoluteExpiresAt'] ?? 'absolute_expires_at',
            regenerateAtColumn: $config['columns']['regenerateAt'] ?? 'regenerate_at',
            replacedByColumn: $config['columns']['replacedBy'] ?? 'replaced_by',
            createdAtColumn: $config['columns']['createdAt'] ?? 'created_at',
            lastActiveAtColumn: $config['columns']['lastActiveAt'] ?? 'last_active_at',
            attributesColumn: $config['columns']['attributes'] ?? 'attributes',
        );
    }
}
