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
        /**
         * @var Config $config
         */
        $config = $container->get('config');
        $config = $config->array(new ConfigPath(ConfigKey::AUTH . '.' . ConfigKey::DENIED), []);

        return new DeniedResponseFactory(
            responseFactory: $container->get(ResponseFactoryInterface::class),
            statusMap: $config['statusMap'] ?? [],
            defaultStatus: $config['defaultStatus'] ?? 401,
        );
    }
}
