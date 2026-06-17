<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\RememberMe\RememberMeTerminationListener;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Psr\Container\ContainerInterface;

final readonly class RememberMeTerminationListenerFactory
{
    public function __invoke(ContainerInterface $container): RememberMeTerminationListener
    {
        return new RememberMeTerminationListener(
            tokenManager: $container->get(RememberMeTokenManagerInterface::class),
        );
    }
}
