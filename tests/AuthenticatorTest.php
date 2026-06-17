<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\Authenticator;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Exception\NoStrategyFoundException;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class AuthenticatorTest extends TestCase
{
    public function testReturnsFirstSuccessfulResultAfterDeniedAttempt(): void
    {
        $payload = new \stdClass();
        $context = new Context();
        $identity = new class implements IdentityInterface {
            public UuidInterface $uuid {
                get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
            }
        };

        $authenticator = new Authenticator(
            new AuthStrategyFixture(true, new AuthenticationResult(new DeniedReason('invalid'))),
            new AuthStrategyFixture(true, new AuthenticationResult($identity)),
        );

        $result = $authenticator->attempt($payload, $context);

        self::assertSame($identity, $result->subject);
    }

    public function testReturnsLastDeniedResultWhenNoStrategySucceeds(): void
    {
        $result = (new Authenticator(
            new AuthStrategyFixture(true, new AuthenticationResult(new DeniedReason('first'))),
            new AuthStrategyFixture(true, new AuthenticationResult(new DeniedReason('last'))),
        ))->attempt(new \stdClass(), new Context());

        self::assertInstanceOf(DeniedReason::class, $result->subject);
        self::assertSame('last', $result->subject->code);
    }

    public function testThrowsWhenNoStrategySupportsPayload(): void
    {
        $this->expectException(NoStrategyFoundException::class);

        (new Authenticator(new AuthStrategyFixture(false, new AuthenticationResult(new DeniedReason('unused')))))
            ->attempt(new \stdClass(), new Context());
    }
}

final readonly class AuthStrategyFixture implements AuthenticationStrategyInterface
{
    public function __construct(
        private bool $supports,
        private AuthenticationResult $result,
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $this->supports;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        return $this->result;
    }
}
