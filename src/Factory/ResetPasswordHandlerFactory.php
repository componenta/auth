<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\PasswordReset\PasswordResetServiceInterface;
use Componenta\Auth\PasswordReset\ResetPasswordHandler;
use Componenta\Stdlib\PasswordHasherInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class ResetPasswordHandlerFactory
{
    public function __invoke(ContainerInterface $container): ResetPasswordHandler
    {
        return new ResetPasswordHandler(
            resetService: $container->get(PasswordResetServiceInterface::class),
            passwordHasher: $container->get(PasswordHasherInterface::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
