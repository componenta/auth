<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\MagicLink\RequestHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class MagicLinkRequestHandlerFactory
{
    public function __invoke(ContainerInterface $container): RequestHandler
    {
        return new RequestHandler(
            requester: $container->get('auth.magicLink.requester'),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
