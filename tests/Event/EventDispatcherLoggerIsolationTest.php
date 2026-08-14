<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Event;

use Componenta\Auth\Event\AuthenticationAttempted;
use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class EventDispatcherLoggerIsolationTest extends TestCase
{
    public function testBrokenLoggerCannotMaskCriticalListenerFailure(): void
    {
        $listenerFailure = new \RuntimeException('critical listener failed');
        $provider = new PriorityListenerProvider();
        $provider->addListener(new LoggerIsolationCriticalListener(
            static function () use ($listenerFailure): void {
                throw $listenerFailure;
            },
        ));
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('error')->willThrowException(
            new \RuntimeException('logger failed'),
        );
        $dispatcher = new EventDispatcher($provider, $logger);

        $this->expectExceptionObject($listenerFailure);
        $dispatcher->dispatchCritical(self::event());
    }

    public function testBrokenLoggerCannotStopLaterBestEffortObserver(): void
    {
        $calls = [];
        $provider = new PriorityListenerProvider();
        $provider->addListener(new LoggerIsolationObserver(
            static function () use (&$calls): void {
                $calls[] = 'failing';
                throw new \RuntimeException('observer failed');
            },
        ), 10);
        $provider->addListener(new LoggerIsolationObserver(
            static function () use (&$calls): void {
                $calls[] = 'later';
            },
        ));
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('error')->willThrowException(
            new \RuntimeException('logger failed'),
        );
        $dispatcher = new EventDispatcher($provider, $logger);

        $dispatcher->dispatchBestEffort(self::event());

        self::assertSame(['failing', 'later'], $calls);
    }

    private static function event(): AuthenticationAttempted
    {
        return new AuthenticationAttempted(
            'test-payload',
            new \DateTimeImmutable('@1000'),
        );
    }
}

final readonly class LoggerIsolationCriticalListener implements CriticalEventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    /** @param \Closure(): void $callback */
    public function __construct(private \Closure $callback)
    {
        $this->events = [AuthenticationAttempted::class];
    }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void {
        ($this->callback)();
    }
}

final readonly class LoggerIsolationObserver implements EventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    /** @param \Closure(): void $callback */
    public function __construct(private \Closure $callback)
    {
        $this->events = [AuthenticationAttempted::class];
    }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void {
        ($this->callback)();
    }
}
