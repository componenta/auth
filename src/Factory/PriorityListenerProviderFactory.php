<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use Psr\Container\ContainerInterface;

final readonly class PriorityListenerProviderFactory
{
    public function __invoke(ContainerInterface $container): PriorityListenerProvider
    {
        $provider = new PriorityListenerProvider();

        /** @var list<class-string> $configured */
        $configured = $container->get(ConfigKey::CONFIG)[ConfigKey::LISTENERS] ?? [];

        foreach (array_values(array_unique($configured)) as $listenerClass) {
            if (!$container->has($listenerClass)) {
                throw new \LogicException(sprintf('Authentication event listener "%s" is not registered.', $listenerClass));
            }

            $listener = $container->get($listenerClass);
            if (!$listener instanceof EventListenerInterface) {
                throw new \LogicException(sprintf(
                    'Authentication event listener "%s" must implement %s.',
                    $listenerClass,
                    EventListenerInterface::class,
                ));
            }

            $provider->addListener($listener);
        }

        return $provider;
    }
}
