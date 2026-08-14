<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\RememberMe\RememberMeTerminationListener;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Psr\Container\ContainerInterface;

final readonly class RememberMeTerminationListenerFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): RememberMeTerminationListener {
        /** @var RememberMeTokenManagerInterface $tokenManager */
        $tokenManager = $container->get(RememberMeTokenManagerInterface::class);

        return new RememberMeTerminationListener($tokenManager);
    }
}
