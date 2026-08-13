<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Exception\AuthenticatorConfigurationException;
use Componenta\Auth\Http\Strategy\RememberMe\CompensatingRememberMeStrategy;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class CompensatingRememberMeStrategyFactory
{
    public function __invoke(ContainerInterface $container): CompensatingRememberMeStrategy
    {
        $config = $container->get(ConfigKey::CONFIG);
        if (!$config instanceof Config) {
            throw new AuthenticatorConfigurationException(
                'The config service must be an instance of Componenta\\Config\\Config.',
            );
        }

        if (!$config->bool(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME . '.' . ConfigKey::ENABLED,
        ), false)) {
            throw new AuthenticatorConfigurationException(
                'CompensatingRememberMeStrategy requires auth.rememberMe.enabled=true.',
            );
        }

        $strategy = $container->get(RememberMeStrategy::class);
        $tokenManager = $container->get(RememberMeTokenManagerInterface::class);
        $sessionManager = $container->get(SessionManagerInterface::class);

        if (!$strategy instanceof RememberMeStrategy) {
            throw new AuthenticatorConfigurationException(sprintf(
                '%s must resolve to the built-in strategy.',
                RememberMeStrategy::class,
            ));
        }
        if (!$tokenManager instanceof RememberMeTokenManagerInterface) {
            throw new AuthenticatorConfigurationException(sprintf(
                '%s must resolve to %s.',
                RememberMeTokenManagerInterface::class,
                RememberMeTokenManagerInterface::class,
            ));
        }
        if (!$sessionManager instanceof SessionManagerInterface) {
            throw new AuthenticatorConfigurationException(sprintf(
                '%s must resolve to %s.',
                SessionManagerInterface::class,
                SessionManagerInterface::class,
            ));
        }

        return new CompensatingRememberMeStrategy(
            $strategy,
            $tokenManager,
            $sessionManager,
        );
    }
}
