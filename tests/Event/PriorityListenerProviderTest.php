<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Event;

use Componenta\Auth\Event\AuthenticationAttempted;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PriorityListenerProviderTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function impossibleSubscriptions(): iterable
    {
        yield 'interface' => [EventInterface::class];
        yield 'abstract class' => [AbstractEventFixture::class];
    }

    #[DataProvider('impossibleSubscriptions')]
    public function testRejectsSubscriptionsThatCannotMatchAnExactEventClass(string $eventType): void
    {
        $provider = new PriorityListenerProvider();
        $listener = self::listener($eventType);
        $this->expectException(\InvalidArgumentException::class);

        $provider->addListener($listener);
    }

    public function testAddingListenersAfterFirstLookupRespectsPriorityAndInsertionOrder(): void
    {
        $provider = new PriorityListenerProvider();
        $low = self::listener();
        $firstHigh = self::listener();
        $secondHigh = self::listener();
        $provider->addListener($low, -5);
        $event = new AuthenticationAttempted('test', new \DateTimeImmutable('@1'));
        self::assertSame([$low], iterator_to_array($provider->provideFor($event), false));

        $provider->addListener($firstHigh, 10);
        $provider->addListener($secondHigh, 10);

        self::assertSame([$firstHigh, $secondHigh, $low], iterator_to_array($provider->provideFor($event), false));
    }

    /** @return iterable<string, array{string}> */
    public static function equivalentClassNames(): iterable
    {
        yield 'leading namespace separator' => ['\\' . AuthenticationAttempted::class];
        yield 'different case' => [strtolower(AuthenticationAttempted::class)];
        yield 'class alias' => [__NAMESPACE__ . '\\AttemptedAliasFixture'];
    }

    #[DataProvider('equivalentClassNames')]
    public function testAcceptedNamesOfTheSameConcreteClassReachTheListener(string $eventType): void
    {
        $event = new AuthenticationAttempted('test', new \DateTimeImmutable('@1'));
        $alias = __NAMESPACE__ . '\\AttemptedAliasFixture';
        if (!class_exists($alias, false)) {
            class_alias(AuthenticationAttempted::class, $alias);
        }
        $provider = new PriorityListenerProvider();
        $listener = self::listener($eventType);
        $provider->addListener($listener);

        self::assertSame([$listener], iterator_to_array($provider->provideFor($event), false));
    }

    public function testExactClassMatchingDoesNotSubscribeToChildEvents(): void
    {
        $provider = new PriorityListenerProvider();
        $listener = self::listener(ConcreteEventFixture::class);
        $provider->addListener($listener);

        self::assertSame([], iterator_to_array(
            $provider->provideFor(new ChildEventFixture(new \DateTimeImmutable('@1'))),
            false,
        ));
        self::assertSame([$listener], iterator_to_array(
            $provider->provideFor(new ConcreteEventFixture(new \DateTimeImmutable('@1'))),
            false,
        ));
    }

    private static function listener(string $eventType = AuthenticationAttempted::class): EventListenerInterface
    {
        return new readonly class($eventType) implements EventListenerInterface {
            public array $events;

            public function __construct(string $eventType)
            {
                $this->events = [$eventType];
            }

            public function handleEvent(EventInterface $event): void {}
        };
    }
}

abstract class AbstractEventFixture implements EventInterface
{
    public \DateTimeImmutable $timestamp;
}

class ConcreteEventFixture implements EventInterface
{
    public function __construct(public \DateTimeImmutable $timestamp) {}
}

final class ChildEventFixture extends ConcreteEventFixture {}
