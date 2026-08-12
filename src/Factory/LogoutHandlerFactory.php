<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class LogoutHandlerFactory
{
    public function __invoke(ContainerInterface $container): LogoutHandler
    {
        /** @var PayloadStorageInterface $storage */
        $storage = $container->get(PayloadStorageInterface::class);
        /** @var SessionManagerInterface $sessionManager */
        $sessionManager = $container->get(SessionManagerInterface::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        $dispatcher = null;

        if ($container->has(EventDispatcher::class)) {
            $candidate = $container->get(EventDispatcher::class);

            if (!$candidate instanceof EventDispatcher) {
                throw new \LogicException(sprintf(
                    '%s must resolve to %s.',
                    EventDispatcher::class,
                    EventDispatcher::class,
                ));
            }

            $dispatcher = $candidate;
        }

        if (!$container->has(ClockInterface::class)) {
            return new LogoutHandler($storage, $sessionManager, $responseFactory, $dispatcher);
        }

        $clock = $container->get(ClockInterface::class);

        if (!$clock instanceof ClockInterface) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ClockInterface::class,
                ClockInterface::class,
            ));
        }

        return new LogoutHandler(
            $storage,
            $sessionManager,
            $responseFactory,
            $dispatcher,
            $clock,
        );
    }
}
