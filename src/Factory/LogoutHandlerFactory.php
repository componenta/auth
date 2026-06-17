<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class LogoutHandlerFactory
{
    public function __invoke(ContainerInterface $container): LogoutHandler
    {
        return new LogoutHandler(
            storage: $container->get(PayloadStorageInterface::class),
            sessionManager: $container->get(SessionManagerInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
            dispatcher: $container->has(EventDispatcher::class)
                ? $container->get(EventDispatcher::class)
                : null,
        );
    }
}
