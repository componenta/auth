<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class DeniedResponseFactoryFactory
{
    public function __invoke(ContainerInterface $container): DeniedResponseFactory
    {
        $config = $container->get(ConfigKey::CONFIG);
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        if (!$responseFactory instanceof ResponseFactoryInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ResponseFactoryInterface::class,
                ResponseFactoryInterface::class,
            ));
        }

        $prefix = ConfigKey::AUTH . '.' . ConfigKey::DENIED;
        $configuredMap = $config->array(new ConfigPath($prefix . '.statusMap'), []);
        $statusMap = [];

        foreach ($configuredMap as $code => $status) {
            if (!is_string($code) || $code === '' || !is_int($status)) {
                throw new \LogicException(
                    'auth.denied.statusMap must contain non-empty string keys and integer HTTP statuses.',
                );
            }

            $statusMap[$code] = $status;
        }

        return new DeniedResponseFactory(
            responseFactory: $responseFactory,
            statusMap: $statusMap,
            defaultStatus: $config->int(new ConfigPath($prefix . '.defaultStatus'), 401),
        );
    }
}
