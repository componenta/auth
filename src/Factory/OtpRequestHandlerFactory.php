<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Otp\OtpRequestQueueInterface;
use Componenta\Auth\Http\Strategy\Otp\RequestHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class OtpRequestHandlerFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): RequestHandler {
        /** @var OtpRequestQueueInterface $queue */
        $queue = $container->get(OtpRequestQueueInterface::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        return new RequestHandler($queue, $responseFactory);
    }
}
