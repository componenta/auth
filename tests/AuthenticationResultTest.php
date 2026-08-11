<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\Session;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthenticationResultTest extends TestCase
{
    public function testRejectsSessionOnDeniedResult(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationResult(
            new DeniedReason('invalid_credentials'),
            session: self::session(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            ),
        );
    }

    public function testRejectsSessionOwnedByAnotherIdentity(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $identity = new AuthenticationResultIdentityFixture(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
        );

        new AuthenticationResult(
            $identity,
            session: self::session(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
            ),
        );
    }

    public function testAcceptsSessionOwnedByIdentity(): void
    {
        $uuid = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $identity = new AuthenticationResultIdentityFixture($uuid);
        $session = self::session($uuid);

        $result = new AuthenticationResult($identity, session: $session);

        self::assertSame($session, $result->session);
    }

    public function testSerializationDoesNotTraverseIdentityOrCredentials(): void
    {
        $uuid = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $identity = new class($uuid) implements IdentityInterface {
            public string $applicationSecret = 'identity-secret';

            public function __construct(public UuidInterface $uuid) {}
        };
        $result = new AuthenticationResult(
            $identity,
            transportPayload: new SessionPayload('session-secret'),
            session: self::session($uuid),
        );

        $json = json_encode($result, JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('identity-secret', $json);
        self::assertStringNotContainsString('session-secret', $json);
        self::assertStringContainsString($uuid->toString(), $json);
        self::assertStringContainsString(SessionPayload::class, $json);
    }

    private static function session(UuidInterface $subjectId): Session
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            id: 'session-id',
            subjectId: $subjectId,
            expiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
            regenerateAt: $now->modify('+5 minutes'),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
        );
    }
}

final readonly class AuthenticationResultIdentityFixture implements IdentityInterface
{
    public function __construct(public UuidInterface $uuid) {}
}
