<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Event;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\Event\AuthenticationAttempted;
use Componenta\Auth\Event\AuthenticationAttemptedListenerInterface;
use Componenta\Auth\Event\AuthenticationSucceeded;
use Componenta\Auth\Event\AuthenticationSucceededListenerInterface;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Componenta\Auth\EventingAuthenticator;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class EventingAuthenticatorTest extends TestCase
{
    public function testGenericEventsContainMetadataButNotCredentialOrIdentityObject(): void
    {
        $identity = new EventingIdentityFixture();
        $inner = $this->createStub(AuthenticatorInterface::class);
        $inner->method('attempt')->willReturn(new AuthenticationResult($identity));
        $listener = new EventCollectorFixture();
        $dispatcher = new EventDispatcher(new EventCollectorProviderFixture($listener));
        $payload = new EventCredentialFixture('secret');
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new DateTimeImmutable('@1000'));

        $result = (new EventingAuthenticator($inner, $dispatcher, $clock))
            ->attempt($payload, new Context());

        self::assertSame($identity, $result->subject);
        self::assertCount(2, $listener->events);
        self::assertInstanceOf(AuthenticationAttempted::class, $listener->events[0]);
        self::assertSame(EventCredentialFixture::class, $listener->events[0]->payloadType);
        self::assertArrayNotHasKey(
            'payload',
            get_object_vars($listener->events[0]),
        );

        $succeeded = $listener->events[1];
        self::assertInstanceOf(AuthenticationSucceeded::class, $succeeded);
        self::assertTrue($succeeded->subjectId->equals($identity->uuid));
        $succeededProperties = get_object_vars($succeeded);
        self::assertArrayNotHasKey('user', $succeededProperties);
        self::assertArrayNotHasKey('identity', $succeededProperties);
        self::assertStringNotContainsString(
            'secret',
            serialize($listener->events),
        );
    }
}

final readonly class EventCredentialFixture
{
    public function __construct(
        #[\SensitiveParameter]
        public string $secret,
    ) {}
}

final class EventingIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}

final class EventCollectorFixture implements
    AuthenticationAttemptedListenerInterface,
    AuthenticationSucceededListenerInterface
{
    /** @var list<EventInterface> */
    public array $events = [];

    #[\Override]
    public function handleEvent(EventInterface $event): void
    {
        $this->events[] = $event;
    }
}

final readonly class EventCollectorProviderFixture implements EventListenerProviderInterface
{
    public function __construct(private EventListenerInterface $listener) {}

    #[\Override]
    public function provideFor(EventInterface $event): iterable
    {
        yield $this->listener;
    }
}
