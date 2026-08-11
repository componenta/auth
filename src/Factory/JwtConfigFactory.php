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
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $prefix = ConfigKey::AUTH . '.' . ConfigKey::JWT;

        return new JwtConfig(
            issuer: $config->string(new ConfigPath($prefix . '.issuer')),
            audience: $config->string(new ConfigPath($prefix . '.audience')),
            type: $config->string(new ConfigPath($prefix . '.type'), 'at+jwt'),
            accessTtl: $config->int(new ConfigPath($prefix . '.accessTtl'), 900),
            refreshTtl: $config->int(new ConfigPath($prefix . '.refreshTtl'), 604800),
            clockSkew: $config->int(new ConfigPath($prefix . '.clockSkew'), 30),
        );
    }
}
