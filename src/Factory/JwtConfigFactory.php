<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class JwtConfigFactory
{
    public function __invoke(ContainerInterface $container): JwtConfig
    {
        /** @var Config $config */
        $config = $container->get('config');
        $jwt = $config->array(new ConfigPath(ConfigKey::AUTH . '.' . ConfigKey::JWT), []);

        return new JwtConfig(
            accessTtl: $jwt['accessTtl'] ?? 900,
            refreshTtl: $jwt['refreshTtl'] ?? 604800,
            issuer: $jwt['issuer'] ?? '',
            audience: $jwt['audience'] ?? '',
        );
    }
}
