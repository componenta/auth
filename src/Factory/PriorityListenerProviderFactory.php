<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\RememberMe\RememberMeRegenerationListener;
use Componenta\Auth\RememberMe\RememberMeTerminationListener;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class PriorityListenerProviderFactory
{
    public function __invoke(ContainerInterface $container): PriorityListenerProvider
    {
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $configured = $config->array(new ConfigPath(ConfigKey::LISTENERS), []);

        if ($config->bool(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME . '.' . ConfigKey::ENABLED,
        ), false)) {
            $configured[] = RememberMeTerminationListener::class;
            $configured[] = RememberMeRegenerationListener::class;
        }

        $listenerIds = [];

        foreach ($configured as $index => $listenerId) {
            if (!is_string($listenerId) || $listenerId === '') {
                throw new \LogicException(sprintf(
                    'auth event listener at index %d must be a non-empty service id.',
                    $index,
                ));
            }

            $listenerIds[$listenerId] = true;
        }

        $provider = new PriorityListenerProvider();

        foreach (array_keys($listenerIds) as $listenerId) {
            if (!$container->has($listenerId)) {
                throw new \LogicException(sprintf(
                    'Authentication event listener "%s" is not registered.',
                    $listenerId,
                ));
            }

            $listener = $container->get($listenerId);

            if (!$listener instanceof EventListenerInterface) {
                throw new \LogicException(sprintf(
                    'Authentication event listener "%s" must implement %s.',
                    $listenerId,
                    EventListenerInterface::class,
                ));
            }

            $provider->addListener($listener);
        }

        return $provider;
    }
}
