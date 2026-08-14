<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\MagicLink\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class JwtMagicLinkTokenHandlerFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): TokenHandler {
        /** @var VerifyExtractor $extractor */
        $extractor = $container->get(VerifyExtractor::class);
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
