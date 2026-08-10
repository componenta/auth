<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\PasswordReset\ForgotPasswordHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class ForgotPasswordHandlerFactory
{
    public function __invoke(ContainerInterface $container): ForgotPasswordHandler
    {
        return new ForgotPasswordHandler(
            queue: $container->get('auth.passwordReset.queue'),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
