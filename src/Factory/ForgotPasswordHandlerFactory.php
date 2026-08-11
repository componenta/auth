<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\PasswordReset\ForgotPasswordHandler;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class ForgotPasswordHandlerFactory
{
    public function __invoke(ContainerInterface $container): ForgotPasswordHandler
    {
        /** @var TokenRequestQueueInterface $queue */
        $queue = $container->get('auth.passwordReset.queue');
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        return new ForgotPasswordHandler($queue, $responseFactory);
    }
}
