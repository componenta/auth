<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Password\TokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Psr\Container\ContainerInterface;

final readonly class JwtPasswordTokenHandlerFactory
{
    public function __invoke(ContainerInterface $container): TokenHandler
    {
        /** @var PasswordExtractor $extractor */
        $extractor = $container->get(PasswordExtractor::class);
        /** @var AuthenticatorInterface $authenticator */
        $authenticator = $container->get(AuthenticatorInterface::class);
        /** @var TokenPairResponse $tokenPair */
        $tokenPair = $container->get(TokenPairResponse::class);
        /** @var DeniedResponseFactoryInterface $denied */
        $denied = $container->get(DeniedResponseFactoryInterface::class);

        return new TokenHandler($extractor, $authenticator, $tokenPair, $denied);
    }
}
