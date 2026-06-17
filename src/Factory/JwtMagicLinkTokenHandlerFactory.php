<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\MagicLink\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class JwtMagicLinkTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): TokenHandler
    {
        return new TokenHandler(
            extractor: $container->get(VerifyExtractor::class),
            strategy: $container->get(MagicLinkStrategy::class),
            tokenPair: $container->get(TokenPairResponse::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
