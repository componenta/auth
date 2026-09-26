<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class AuthenticationResultTest extends TestCase
{
    public function testRejectsStateOnDeniedResult(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationResult(
            new DeniedReason('invalid_credentials'),
            state: new AuthenticationStateFixture(),
        );
    }

    public function testRejectsEvidenceOnDeniedResult(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationResult(
            new DeniedReason('invalid_credentials'),
            evidence: new AuthenticationEvidence(['password']),
        );
    }

    public function testRejectsSuccessfulResultWithoutEvidence(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationResult(
            new AuthenticationResultIdentityFixture(
                Uuid::fromString(
                    '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
                ),
            ),
        );
    }

    public function testAcceptsOneTypedAuthenticationStateObject(): void
    {
        $identity = new AuthenticationResultIdentityFixture(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
        );
        $state = new AuthenticationStateFixture();
        $evidence = new AuthenticationEvidence(['custom']);

        $result = new AuthenticationResult(
            $identity,
            state: $state,
            evidence: $evidence,
        );

        self::assertSame($state, $result->state);
        self::assertSame($evidence, $result->evidence);
    }

    public function testSerializationDoesNotTraverseIdentityPayloadOrState(): void
    {
        $uuid = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $identity = new class($uuid) implements IdentityInterface {
            public string $applicationSecret = 'identity-secret';

            public function __construct(public UuidInterface $uuid) {}
        };
        $payload = new AuthenticationPayloadFixture();
        $state = new AuthenticationStateFixture();
        $result = new AuthenticationResult(
            $identity,
            transportPayload: $payload,
            state: $state,
            evidence: new AuthenticationEvidence(['session']),
        );

        $json = json_encode($result, JSON_THROW_ON_ERROR);
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertStringNotContainsString('identity-secret', $json);
        self::assertStringNotContainsString('transport-secret', $json);
        self::assertStringNotContainsString('state-secret', $json);
        self::assertSame($uuid->toString(), $decoded['subjectId'] ?? null);
        self::assertSame(
            AuthenticationPayloadFixture::class,
            $decoded['transportPayloadType'] ?? null,
        );
        self::assertSame(
            AuthenticationStateFixture::class,
            $decoded['stateType'] ?? null,
        );
        self::assertSame(['session'], $decoded['evidence']['methods'] ?? null);
    }
}

final readonly class AuthenticationResultIdentityFixture implements IdentityInterface
{
    public function __construct(public UuidInterface $uuid) {}
}

final class AuthenticationPayloadFixture
{
    public string $secret = 'transport-secret';
}

final class AuthenticationStateFixture implements AuthenticationStateInterface
{
    public string $secret = 'state-secret';
}
