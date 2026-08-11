<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\VerifyHandler;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class OtpVerifyHandlerFactory
{
    public function __invoke(ContainerInterface $container): VerifyHandler
    {
        /** @var OtpExtractor $extractor */
        $extractor = $container->get(OtpExtractor::class);
        /** @var AuthenticatorInterface $authenticator */
        $authenticator = $container->get(AuthenticatorInterface::class);
        /** @var SessionManagerInterface $sessionManager */
        $sessionManager = $container->get(SessionManagerInterface::class);
        /** @var PayloadStorageInterface $storage */
        $storage = $container->get(PayloadStorageInterface::class);
        /** @var DeniedResponseFactoryInterface $deniedResponseFactory */
        $deniedResponseFactory = $container->get(DeniedResponseFactoryInterface::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);
        /** @var SessionAttributeExtractorInterface $attributeExtractor */
        $attributeExtractor = $container->get(SessionAttributeExtractorInterface::class);

        return new VerifyHandler(
            $extractor,
            $authenticator,
            $sessionManager,
            $storage,
            $deniedResponseFactory,
            $responseFactory,
            $attributeExtractor,
        );
    }
}
