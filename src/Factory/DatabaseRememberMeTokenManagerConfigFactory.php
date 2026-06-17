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
    public function lazy(ContainerInterface $container, ProxyFactoryInterface $proxyFactory): object
    {
        return $proxyFactory->makeProxy(
            DatabaseRememberMeTokenManagerConfig::class,
            fn(object $proxy): DatabaseRememberMeTokenManagerConfig => $this->__invoke($container),
        );
    }

    public function __invoke(ContainerInterface $container): DatabaseRememberMeTokenManagerConfig
    {
        /** @var Config $config */
        $config = $container->get('config');
        $config = $config->array(new ConfigPath(ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME), []);

        return new DatabaseRememberMeTokenManagerConfig(
            table: $config['table'] ?? 'remember_me_tokens',
            dateFormat: $config['dateFormat'] ?? 'Y-m-d H:i:s',
            ttl: $config['ttl'] ?? 2592000,
            idColumn: $config['columns']['id'] ?? 'id',
            userIdColumn: $config['columns']['userId'] ?? 'user_id',
            tokenColumn: $config['columns']['token'] ?? 'token',
            sessionIdColumn: $config['columns']['sessionId'] ?? 'session_id',
            expiresAtColumn: $config['columns']['expiresAt'] ?? 'expires_at',
            createdAtColumn: $config['columns']['createdAt'] ?? 'created_at',
        );
    }
}
