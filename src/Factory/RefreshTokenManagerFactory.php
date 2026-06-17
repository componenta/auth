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
        return new RefreshTokenManager(
            store: $container->get(RefreshTokenStoreInterface::class),
            generator: $container->get(RefreshTokenGenerator::class),
            config: $container->get(JwtConfig::class),
        );
    }
}
