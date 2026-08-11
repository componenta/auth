<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Psr\Container\ContainerInterface;

final readonly class RefreshTokenManagerFactory
{
    public function __invoke(ContainerInterface $container): RefreshTokenManager
    {
        /** @var RefreshTokenStoreInterface $store */
        $store = $container->get(RefreshTokenStoreInterface::class);
        /** @var RefreshTokenGenerator $generator */
        $generator = $container->get(RefreshTokenGenerator::class);
        /** @var JwtConfig $config */
        $config = $container->get(JwtConfig::class);

        return new RefreshTokenManager($store, $generator, $config);
    }
}
