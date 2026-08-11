<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStoreConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Cycle\Database\DatabaseInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseCodeStoreFactory
{
    public function __invoke(ContainerInterface $container): DatabaseCodeStore
    {
        $database = $container->get(DatabaseInterface::class);
        $storeConfig = $container->get(DatabaseCodeStoreConfig::class);
        $config = $container->get(ConfigKey::CONFIG);

        if (!$database instanceof DatabaseInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseInterface::class,
                DatabaseInterface::class,
            ));
        }

        if (!$storeConfig instanceof DatabaseCodeStoreConfig) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseCodeStoreConfig::class,
                DatabaseCodeStoreConfig::class,
            ));
        }

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $hmacKey = $config->string(new ConfigPath(
            ConfigKey::AUTH
            . '.'
            . ConfigKey::OTP
            . '.'
            . ConfigKey::HMAC_KEY,
        ));

        if (strlen($hmacKey) < 32) {
            throw new \LogicException(
                'auth.otp.hmacKey must contain at least 32 bytes when the built-in SQL code store is used.',
            );
        }

        return new DatabaseCodeStore(
            $database,
            $hmacKey,
            $storeConfig,
        );
    }
}
