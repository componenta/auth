<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Otp\OtpRequester;
use Componenta\Auth\Http\Strategy\Otp\RequestHandler;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class OtpRequestHandlerFactory
{
    public function __invoke(ContainerInterface $container): RequestHandler
    {
        return new RequestHandler(
            requester: $container->get(OtpRequester::class),
            responseFactory: $container->get(ResponseFactoryInterface::class),
        );
    }
}
