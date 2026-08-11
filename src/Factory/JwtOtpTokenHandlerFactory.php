<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Otp\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class JwtOtpTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): TokenHandler
    {
        /** @var OtpExtractor $extractor */
        $extractor = $container->get(OtpExtractor::class);
        /** @var AuthenticatorInterface $authenticator */
        $authenticator = $container->get(AuthenticatorInterface::class);
        /** @var TokenPairResponse $tokenPair */
        $tokenPair = $container->get(TokenPairResponse::class);
        /** @var DeniedResponseFactoryInterface $denied */
        $denied = $container->get(DeniedResponseFactoryInterface::class);
        /** @var ResponseFactoryInterface $responses */
        $responses = $container->get(ResponseFactoryInterface::class);

        return new TokenHandler(
            $extractor,
            $authenticator,
            $tokenPair,
            $denied,
            $responses,
        );
    }
}
