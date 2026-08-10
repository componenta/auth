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
            throw new \LogicException('The config service must be Componenta\\Config\\Config.');
        }

        $jwt = $config->array(new ConfigPath(ConfigKey::AUTH . '.' . ConfigKey::JWT), []);

        return new JwtConfig(
            issuer: self::requiredString($jwt, 'issuer'),
            audience: self::requiredString($jwt, 'audience'),
            type: self::string($jwt, 'type', 'at+jwt'),
            accessTtl: self::integer($jwt, 'accessTtl', 900),
            refreshTtl: self::integer($jwt, 'refreshTtl', 604800),
            clockSkew: self::integer($jwt, 'clockSkew', 30),
        );
    }

    /** @param array<string, mixed> $config */
    private static function requiredString(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (!is_string($value) || $value === '') {
            throw new \LogicException(sprintf('auth.jwt.%s must be a non-empty string.', $key));
        }

        return $value;
    }

    /** @param array<string, mixed> $config */
    private static function string(array $config, string $key, string $default): string
    {
        $value = $config[$key] ?? $default;

        if (!is_string($value) || $value === '') {
            throw new \LogicException(sprintf('auth.jwt.%s must be a non-empty string.', $key));
        }

        return $value;
    }

    /** @param array<string, mixed> $config */
    private static function integer(array $config, string $key, int $default): int
    {
        $value = $config[$key] ?? $default;

        if (!is_int($value)) {
            throw new \LogicException(sprintf('auth.jwt.%s must be an integer.', $key));
        }

        return $value;
    }
}
