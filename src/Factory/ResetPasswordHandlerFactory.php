<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\PasswordReset\PasswordResetServiceInterface;
use Componenta\Auth\PasswordReset\ResetPasswordHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class ResetPasswordHandlerFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): ResetPasswordHandler {
        $resetService = $container->get(PasswordResetServiceInterface::class);
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        if (!$resetService instanceof PasswordResetServiceInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                PasswordResetServiceInterface::class,
                PasswordResetServiceInterface::class,
            ));
        }

        if (!$responseFactory instanceof ResponseFactoryInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ResponseFactoryInterface::class,
                ResponseFactoryInterface::class,
            ));
        }

        return new ResetPasswordHandler($resetService, $responseFactory);
    }
}
