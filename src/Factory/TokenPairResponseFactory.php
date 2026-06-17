<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class TokenPairResponseFactory
{
    public function __invoke(ContainerInterface $container): TokenPairResponse
    {
        return new TokenPairResponse(
            signer: $container->get(SignerInterface::class),
            refreshManager: $container->get(RefreshTokenManager::class),
            config: $container->get(JwtConfig::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
