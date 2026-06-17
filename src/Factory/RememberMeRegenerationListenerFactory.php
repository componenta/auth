<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\RememberMe\RememberMeRegenerationListener;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Psr\Container\ContainerInterface;

final readonly class RememberMeRegenerationListenerFactory
{
    public function __invoke(ContainerInterface $container): RememberMeRegenerationListener
    {
        return new RememberMeRegenerationListener(
            tokenManager: $container->get(RememberMeTokenManagerInterface::class),
        );
    }
}
