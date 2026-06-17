<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Event\PriorityListenerProvider;
use Psr\Container\ContainerInterface;

final readonly class PriorityListenerProviderFactory
{
    public function __invoke(ContainerInterface $container): PriorityListenerProvider
    {
        $provider = new PriorityListenerProvider();

        /** @var list<class-string> $listeners */
        $listeners = $container->get(ConfigKey::CONFIG)[ConfigKey::LISTENERS] ?? [];

        foreach ($listeners as $listenerClass) {
            if ($container->has($listenerClass)) {
                $provider->addListener($container->get($listenerClass));
            }
        }

        return $provider;
    }
}
