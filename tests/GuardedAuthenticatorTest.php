<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\GuardedAuthenticator;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class GuardedAuthenticatorTest extends TestCase
{
    public function testPreservesSuccessfulResultWhenEveryGuardAllows(): void
    {
        $identity = new GuardedIdentityFixture();
        $evidence = new AuthenticationEvidence(['webauthn'], ['user_verified']);
        $result = new AuthenticationResult($identity, evidence: $evidence);
        $authenticator = new GuardedAuthenticator(
            new FixedAuthenticatorFixture($result),
            new FixedGuardFixture(null),
        );

        self::assertSame(
            $result,
            $authenticator->attempt(new \stdClass(), new Context()),
        );
    }

    public function testReturnsFirstGuardDenial(): void
    {
        $identity = new GuardedIdentityFixture();
        $authenticator = new GuardedAuthenticator(
            new FixedAuthenticatorFixture(new AuthenticationResult(
                $identity,
                evidence: new AuthenticationEvidence(['password']),
            )),
            new FixedGuardFixture(new DeniedReason('user_disabled')),
            new FixedGuardFixture(new DeniedReason('should_not_run')),
        );

        $result = $authenticator->attempt(new \stdClass(), new Context());

        self::assertInstanceOf(DeniedReason::class, $result->subject);
        self::assertSame('user_disabled', $result->subject->code);
        self::assertNull($result->evidence);
    }

    public function testDoesNotRunGuardsForDeniedAuthentication(): void
    {
        $guard = new CountingGuardFixture();
        $denied = new AuthenticationResult(new DeniedReason('invalid'));
        $authenticator = new GuardedAuthenticator(
            new FixedAuthenticatorFixture($denied),
            $guard,
        );

        self::assertSame(
            $denied,
            $authenticator->attempt(new \stdClass(), new Context()),
        );
        self::assertSame(0, $guard->checks);
    }
}

final readonly class FixedAuthenticatorFixture implements AuthenticatorInterface
{
    public function __construct(private AuthenticationResult $result) {}

    public function attempt(
        object $payload,
        ContextInterface $context,
    ): AuthenticationResult {
        return $this->result;
    }
}

final readonly class FixedGuardFixture implements AuthenticationGuardInterface
{
    public function __construct(private ?DeniedReason $denial) {}

    public function check(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): ?DeniedReason {
        return $this->denial;
    }
}

final class CountingGuardFixture implements AuthenticationGuardInterface
{
    public int $checks = 0;

    public function check(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): ?DeniedReason {
        ++$this->checks;

        return null;
    }
}

final class GuardedIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}
