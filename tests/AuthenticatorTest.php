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
    public function testExplicitSoftFailureContinuesToLaterStrategy(): void
    {
        $identity = new class implements IdentityInterface {
            public UuidInterface $uuid {
                get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
            }
        };
        $authenticator = new Authenticator(
            new AuthStrategyFixture(true, new AuthenticationResult(
                subject: new DeniedReason('invalid'),
                continueOnFailure: true,
            )),
            new AuthStrategyFixture(true, new AuthenticationResult($identity)),
        );

        self::assertSame(
            $identity,
            $authenticator->attempt(new \stdClass(), new Context())->subject,
        );
    }

    public function testTerminalDenialStopsTheChain(): void
    {
        $second = new CountingAuthStrategyFixture(
            new AuthenticationResult(new DeniedReason('second')),
        );
        $result = (new Authenticator(
            new AuthStrategyFixture(
                true,
                new AuthenticationResult(new DeniedReason('terminal')),
            ),
            $second,
        ))->attempt(new \stdClass(), new Context());

        self::assertInstanceOf(DeniedReason::class, $result->subject);
        self::assertSame('terminal', $result->subject->code);
        self::assertSame(0, $second->attempts);
    }

    public function testReturnsLastSoftDenialWhenNoStrategySucceeds(): void
    {
        $result = (new Authenticator(
            new AuthStrategyFixture(true, new AuthenticationResult(
                subject: new DeniedReason('first'),
                continueOnFailure: true,
            )),
            new AuthStrategyFixture(true, new AuthenticationResult(
                subject: new DeniedReason('last'),
                continueOnFailure: true,
            )),
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

final class CountingAuthStrategyFixture implements AuthenticationStrategyInterface
{
    public int $attempts = 0;

    public function __construct(private AuthenticationResult $result) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return true;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        ++$this->attempts;

        return $this->result;
    }
}
