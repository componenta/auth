<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\JwtUserProviderInterface;
use Componenta\Auth\Http\Strategy\Jwt\RefreshHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class RefreshHandlerFactory
{
    public function __invoke(ContainerInterface $container): RefreshHandler
    {
        return new RefreshHandler(
            refreshManager: $container->get(RefreshTokenManager::class),
            provider: $container->get(JwtUserProviderInterface::class),
            signer: $container->get(SignerInterface::class),
            config: $container->get(JwtConfig::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
