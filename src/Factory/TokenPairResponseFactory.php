<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class TokenPairResponseFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): TokenPairResponse {
        /** @var SignerInterface $signer */
        $signer = $container->get(SignerInterface::class);
        /** @var RefreshTokenManager $refreshManager */
        $refreshManager = $container->get(RefreshTokenManager::class);
        /** @var JwtConfig $config */
        $config = $container->get(JwtConfig::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        if (!$container->has(ClockInterface::class)) {
            return new TokenPairResponse($signer, $refreshManager, $config, $responseFactory);
        }

        $clock = $container->get(ClockInterface::class);

        if (!$clock instanceof ClockInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ClockInterface::class,
                ClockInterface::class,
            ));
        }

        return new TokenPairResponse(
            $signer,
            $refreshManager,
            $config,
            $responseFactory,
            $clock,
        );
    }
}
