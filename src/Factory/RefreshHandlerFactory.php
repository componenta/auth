<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\JwtUserProviderInterface;
use Componenta\Auth\Http\Strategy\Jwt\RefreshHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class RefreshHandlerFactory
{
    public function __invoke(ContainerInterface $container): RefreshHandler
    {
        /** @var RefreshTokenManager $refreshManager */
        $refreshManager = $container->get(RefreshTokenManager::class);
        /** @var JwtUserProviderInterface $provider */
        $provider = $container->get(JwtUserProviderInterface::class);
        /** @var SignerInterface $signer */
        $signer = $container->get(SignerInterface::class);
        /** @var JwtConfig $config */
        $config = $container->get(JwtConfig::class);
        /** @var DeniedResponseFactoryInterface $deniedResponseFactory */
        $deniedResponseFactory = $container->get(DeniedResponseFactoryInterface::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        if (!$container->has(ClockInterface::class)) {
            return new RefreshHandler(
                $refreshManager,
                $provider,
                $signer,
                $config,
                $deniedResponseFactory,
                $responseFactory,
            );
        }

        $clock = $container->get(ClockInterface::class);

        if (!$clock instanceof ClockInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ClockInterface::class,
                ClockInterface::class,
            ));
        }

        return new RefreshHandler(
            $refreshManager,
            $provider,
            $signer,
            $config,
            $deniedResponseFactory,
            $responseFactory,
            $clock,
        );
    }
}
