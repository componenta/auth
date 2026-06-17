<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpStrategy;
use Componenta\Auth\Http\Strategy\Otp\VerifyHandler;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class OtpVerifyHandlerFactory
{
    public function __invoke(ContainerInterface $container): VerifyHandler
    {
        return new VerifyHandler(
            extractor: $container->get(OtpExtractor::class),
            strategy: $container->get(OtpStrategy::class),
            sessionManager: $container->get(SessionManagerInterface::class),
            storage: $container->get(PayloadStorageInterface::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
