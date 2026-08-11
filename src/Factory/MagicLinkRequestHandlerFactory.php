<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\MagicLink\RequestHandler;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class MagicLinkRequestHandlerFactory
{
    public function __invoke(ContainerInterface $container): RequestHandler
    {
        /** @var TokenRequestQueueInterface $queue */
        $queue = $container->get('auth.magicLink.queue');
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        return new RequestHandler($queue, $responseFactory);
    }
}
