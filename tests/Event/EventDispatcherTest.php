<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Event;

use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\EventListenerProviderInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class EventDispatcherTest extends TestCase
{
    public function testNonCriticalFailureIsIsolatedAndRemainingListenerRuns(): void
    {
        $ran = false;
        $dispatcher = new EventDispatcher(new ListenerProviderFixture([
            new ThrowingListenerFixture(),
            new CallbackListenerFixture(static function () use (&$ran): void { $ran = true; }),
        ]));

        $dispatcher->dispatch(new EventFixture());

        self::assertTrue($ran);
    }

    public function testCriticalFailureDoesNotPublishBestEffortObservers(): void
    {
        $observerRan = false;
        $dispatcher = new EventDispatcher(new ListenerProviderFixture([
            new CallbackListenerFixture(static function () use (&$observerRan): void { $observerRan = true; }),
            new CriticalThrowingListenerFixture(),
        ]));

        try {
            $dispatcher->dispatch(new EventFixture());
            self::fail('Critical listener failure was not surfaced.');
        } catch (\RuntimeException $exception) {
            self::assertSame('critical failure', $exception->getMessage());
            self::assertFalse($observerRan);
        }
    }

    public function testCriticalFailureStopsLaterCriticalParticipants(): void
    {
        $laterCriticalRan = false;
        $dispatcher = new EventDispatcher(new ListenerProviderFixture([
            new CriticalThrowingListenerFixture(),
            new CriticalCallbackListenerFixture(
                static function () use (&$laterCriticalRan): void {
                    $laterCriticalRan = true;
                },
            ),
        ]));

        try {
            $dispatcher->dispatchCritical(new EventFixture());
            self::fail('Critical listener failure was not surfaced.');
        } catch (\RuntimeException $exception) {
            self::assertSame('critical failure', $exception->getMessage());
            self::assertFalse($laterCriticalRan);
        }
    }

    public function testCriticalPhaseRunsBeforeBestEffortObservers(): void
    {
        $calls = [];
        $dispatcher = new EventDispatcher(new ListenerProviderFixture([
            new CallbackListenerFixture(static function () use (&$calls): void { $calls[] = 'observer'; }),
            new CriticalCallbackListenerFixture(static function () use (&$calls): void { $calls[] = 'critical'; }),
        ]));

        $dispatcher->dispatch(new EventFixture());

        self::assertSame(['critical', 'observer'], $calls);
    }

    public function testObserverModeRunsAllListenersAndIsolatesCriticalMarkerFailure(): void
    {
        $ran = false;
        $dispatcher = new EventDispatcher(new ListenerProviderFixture([
            new CriticalThrowingListenerFixture(),
            new CallbackListenerFixture(static function () use (&$ran): void { $ran = true; }),
        ]));

        $dispatcher->dispatchObservers(new EventFixture());

        self::assertTrue($ran);
    }
}

final readonly class EventFixture implements EventInterface
{
    public DateTimeImmutable $timestamp;

    public function __construct()
    {
        $this->timestamp = new DateTimeImmutable('@1');
    }
}

final readonly class ListenerProviderFixture implements EventListenerProviderInterface
{
    /** @param list<EventListenerInterface> $listeners */
    public function __construct(private array $listeners) {}

    public function provideFor(EventInterface $event): iterable
    {
        return $this->listeners;
    }
}

class ThrowingListenerFixture implements EventListenerInterface
{
    public array $events {
        get => [EventFixture::class];
    }

    public function handleEvent(EventInterface $event): void
    {
        throw new \RuntimeException('observer failure');
    }
}

final class CriticalThrowingListenerFixture extends ThrowingListenerFixture implements CriticalEventListenerInterface
{
    public function handleEvent(EventInterface $event): void
    {
        throw new \RuntimeException('critical failure');
    }
}

final readonly class CallbackListenerFixture implements EventListenerInterface
{
    public array $events {
        get => [EventFixture::class];
    }

    /** @param \Closure(): void $callback */
    public function __construct(private \Closure $callback) {}

    public function handleEvent(EventInterface $event): void
    {
        ($this->callback)();
    }
}

final readonly class CriticalCallbackListenerFixture implements CriticalEventListenerInterface
{
    public array $events {
        get => [EventFixture::class];
    }

    /** @param \Closure(): void $callback */
    public function __construct(private \Closure $callback) {}

    public function handleEvent(EventInterface $event): void
    {
        ($this->callback)();
    }
}
