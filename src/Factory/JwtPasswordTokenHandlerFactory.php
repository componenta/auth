<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Password\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordStrategy;
use Psr\Container\ContainerInterface;

final readonly class JwtPasswordTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): TokenHandler
    {
        return new TokenHandler(
            extractor: $container->get(PasswordExtractor::class),
            strategy: $container->get(PasswordStrategy::class),
            tokenPair: $container->get(TokenPairResponse::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
        );
    }
}
