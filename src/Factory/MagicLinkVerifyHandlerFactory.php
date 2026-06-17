<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class MagicLinkVerifyHandlerFactory
{
    public function __invoke(ContainerInterface $container): VerifyHandler
    {
        return new VerifyHandler(
            extractor: $container->get(VerifyExtractor::class),
            strategy: $container->get(MagicLinkStrategy::class),
            sessionManager: $container->get(SessionManagerInterface::class),
            storage: $container->get(PayloadStorageInterface::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
