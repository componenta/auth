<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStoreConfig;
use Cycle\Database\DatabaseInterface;
use Psr\Container\ContainerInterface;

final readonly class DatabaseRefreshTokenStoreFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DatabaseRefreshTokenStore {
        $database = $container->get(DatabaseInterface::class);
        $config = $container->get(DatabaseRefreshTokenStoreConfig::class);

        if (!$database instanceof DatabaseInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseInterface::class,
                DatabaseInterface::class,
            ));
        }

        if (!$config instanceof DatabaseRefreshTokenStoreConfig) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                DatabaseRefreshTokenStoreConfig::class,
                DatabaseRefreshTokenStoreConfig::class,
            ));
        }

        return new DatabaseRefreshTokenStore($database, $config);
    }
}
