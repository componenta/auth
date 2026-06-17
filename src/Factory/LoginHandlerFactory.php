<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Password\LoginHandler;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordStrategy;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class LoginHandlerFactory
{
    public function __invoke(ContainerInterface $container): LoginHandler
    {
        $tokenManager = $container->has(RememberMeTokenManagerInterface::class)
            ? $container->get(RememberMeTokenManagerInterface::class)
            : null;

        return new LoginHandler(
            extractor: $container->get(PasswordExtractor::class),
            strategy: $container->get(PasswordStrategy::class),
            sessionManager: $container->get(SessionManagerInterface::class),
            storage: $container->get(PayloadStorageInterface::class),
            deniedResponseFactory: $container->get(DeniedResponseFactoryInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
            tokenManager: $tokenManager,
            attributeExtractor: $container->get(SessionAttributeExtractorInterface::class),
        );
    }
}
