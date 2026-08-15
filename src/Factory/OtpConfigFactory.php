<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class OtpConfigFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): OtpConfig {
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $prefix = ConfigKey::AUTH . '.' . ConfigKey::OTP;

        return new OtpConfig(
            length: $config->int(new ConfigPath($prefix . '.length'), 6),
            ttl: $config->int(new ConfigPath($prefix . '.ttl'), 300),
            maxAttempts: $config->int(
                new ConfigPath($prefix . '.maxAttempts'),
                5,
            ),
        );
    }
}
