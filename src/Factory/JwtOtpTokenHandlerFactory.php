<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Otp\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpStrategy;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class JwtOtpTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): TokenHandler
    {
        return new TokenHandler(
            extractor: $container->get(OtpExtractor::class),
            strategy: $container->get(OtpStrategy::class),
            tokenPair: $container->get(TokenPairResponse::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
