<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\Authenticator;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigKey;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\EventingAuthenticator;
use Componenta\Auth\Exception\AuthenticatorConfigurationException;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

/** Builds the security-sensitive strategy chain in explicit configured order. */
final readonly class AuthenticatorFactory
{
    public function __invoke(ContainerInterface $container): AuthenticatorInterface
    {
        $config = $container->get(ConfigKey::CONFIG);
        if (!$config instanceof Config) {
            throw new AuthenticatorConfigurationException('The config service must be an instance of Componenta\\Config\\Config.');
        }

        $ids = $config->array(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::STRATEGIES,
        ), []);

        if ($ids === []) {
            throw new AuthenticatorConfigurationException('auth.strategies must contain at least one service id.');
        }

        $rememberMeEnabled = $config->bool(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME . '.' . ConfigKey::ENABLED,
        ), false);
        $seen = [];
        $strategies = [];

        foreach ($ids as $index => $id) {
            if (!is_string($id) || $id === '') {
                throw new AuthenticatorConfigurationException(sprintf(
                    'auth.strategies[%d] must be a non-empty service id.',
                    $index,
                ));
            }
            if (isset($seen[$id])) {
                throw new AuthenticatorConfigurationException(sprintf(
                    'Duplicate authentication strategy service id "%s".',
                    $id,
                ));
            }
            if (!$container->has($id)) {
                throw new AuthenticatorConfigurationException(sprintf(
                    'Authentication strategy service "%s" is not registered.',
                    $id,
                ));
            }

            $strategy = $container->get($id);
            if (!$strategy instanceof AuthenticationStrategyInterface) {
                throw new AuthenticatorConfigurationException(sprintf(
                    'Service "%s" must implement %s; %s given.',
                    $id,
                    AuthenticationStrategyInterface::class,
                    get_debug_type($strategy),
                ));
            }

            if ($strategy instanceof RememberMeStrategy && !$rememberMeEnabled) {
                throw new AuthenticatorConfigurationException(
                    'The built-in RememberMeStrategy requires auth.rememberMe.enabled=true so its critical lifecycle listeners are active.',
                );
            }

            $seen[$id] = true;
            $strategies[] = $strategy;
        }

        $authenticator = new Authenticator(...$strategies);
        $eventsEnabled = $config->bool(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::EVENTS,
        ), true);

        if (!$eventsEnabled) {
            return $authenticator;
        }

        $dispatcher = $container->get(EventDispatcher::class);

        if (!$dispatcher instanceof EventDispatcher) {
            throw new AuthenticatorConfigurationException(sprintf(
                '%s must resolve to %s.',
                EventDispatcher::class,
                EventDispatcher::class,
            ));
        }

        return new EventingAuthenticator($authenticator, $dispatcher);
    }
}
