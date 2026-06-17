<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RevokeHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class RevokeHandlerFactory
{
    public function __invoke(ContainerInterface $container): RevokeHandler
    {
        return new RevokeHandler(
            refreshManager: $container->get(RefreshTokenManager::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
