<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Event;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Event\AuthenticationSucceeded;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Componenta\Auth\EventingAuthenticator;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class EventProviderIsolationTest extends TestCase
{
    public function testSynchronousObserverProviderFailureDoesNotAbortCompletedAuthentication(): void
    {
        $inner = self::authenticator();
        $provider = new class implements EventListenerProviderInterface {
            public function provideFor(EventInterface $event): iterable
            {
                if ($event instanceof AuthenticationSucceeded) {
                    throw new \RuntimeException('observer provider unavailable');
                }

                return [];
            }
        };

        $result = (new EventingAuthenticator($inner, new EventDispatcher($provider)))
            ->attempt(new \stdClass(), new Context());

        self::assertTrue($inner->committed);
        self::assertInstanceOf(IdentityInterface::class, $result->subject);
    }

    public function testDeferredObserverProviderFailureDoesNotAbortCompletedAuthentication(): void
    {
        $inner = self::authenticator();
        $provider = new class implements EventListenerProviderInterface {
            public bool $observed = false;

            public function provideFor(EventInterface $event): iterable
            {
                if (!$event instanceof AuthenticationSucceeded) {
                    return;
                }

                yield new class($this) implements EventListenerInterface {
                    public array $events {
                        get => [AuthenticationSucceeded::class];
                    }

                    public function __construct(private object $owner) {}

                    public function handleEvent(EventInterface $event): void
                    {
                        $this->owner->observed = true;
                    }
                };

                throw new \RuntimeException('deferred observer provider unavailable');
            }
        };

        $result = (new EventingAuthenticator($inner, new EventDispatcher($provider)))
            ->attempt(new \stdClass(), new Context());

        self::assertTrue($inner->committed);
        self::assertTrue($provider->observed);
        self::assertInstanceOf(IdentityInterface::class, $result->subject);
    }

    public function testCriticalProviderFailureStillPropagates(): void
    {
        $failure = new \RuntimeException('critical provider unavailable');
        $provider = new class($failure) implements EventListenerProviderInterface {
            public function __construct(private \RuntimeException $failure) {}

            public function provideFor(EventInterface $event): iterable
            {
                throw $this->failure;
            }
        };

        $this->expectExceptionObject($failure);

        (new EventDispatcher($provider))->dispatchCritical(
            new AuthenticationSucceeded(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                \stdClass::class,
                new \DateTimeImmutable('@1000'),
            ),
        );
    }

    public function testBestEffortProviderFailureIsIsolatedAndLogged(): void
    {
        $failure = new \RuntimeException('observer provider unavailable');
        $provider = new class($failure) implements EventListenerProviderInterface {
            public function __construct(private \RuntimeException $failure) {}

            public function provideFor(EventInterface $event): iterable
            {
                throw $this->failure;
            }
        };
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error')->with(
            self::isString(),
            self::callback(static fn(array $context): bool =>
                $context['exception'] === $failure && $context['critical'] === false),
        );

        (new EventDispatcher($provider, $logger))->dispatchBestEffort(
            new AuthenticationSucceeded(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                \stdClass::class,
                new \DateTimeImmutable('@1000'),
            ),
        );
    }

    public function testBrokenLoggerCannotConvertObserverProviderFailureToAuthFailure(): void
    {
        $inner = self::authenticator();
        $provider = new class implements EventListenerProviderInterface {
            public function provideFor(EventInterface $event): iterable
            {
                throw new \RuntimeException('observer provider unavailable');
            }
        };
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('error')->willThrowException(new \RuntimeException('logger unavailable'));

        $result = (new EventingAuthenticator($inner, new EventDispatcher($provider, $logger)))
            ->attempt(new \stdClass(), new Context());

        self::assertTrue($inner->committed);
        self::assertInstanceOf(IdentityInterface::class, $result->subject);
    }

    private static function authenticator(): AuthenticatorInterface
    {
        return new class implements AuthenticatorInterface {
            public bool $committed = false;

            public function attempt(object $payload, ContextInterface $context): AuthenticationResult
            {
                $identity = new class implements IdentityInterface {
                    public UuidInterface $uuid {
                        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
                    }
                };
                $this->committed = true;

                return new AuthenticationResult(
                    $identity,
                    evidence: new AuthenticationEvidence(['test']),
                );
            }
        };
    }
}
