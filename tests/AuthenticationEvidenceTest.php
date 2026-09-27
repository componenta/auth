<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationEvidence;
use PHPUnit\Framework\TestCase;

final class AuthenticationEvidenceTest extends TestCase
{
    public function testKeepsBoundedUniqueMethodsAndCapabilities(): void
    {
        $evidence = new AuthenticationEvidence(
            methods: ['otp.email', 'otp.email'],
            capabilities: ['possession', 'phishing_resistant', 'possession'],
        );

        self::assertSame(['otp.email'], $evidence->methods);
        self::assertSame(
            ['possession', 'phishing_resistant'],
            $evidence->capabilities,
        );
        self::assertTrue($evidence->hasMethod('otp.email'));
        self::assertTrue($evidence->hasCapability('phishing_resistant'));
        self::assertFalse($evidence->hasCapability('user_verified'));
    }

    public function testMergeCombinesEvidenceWithoutChangingInputs(): void
    {
        $initial = new AuthenticationEvidence(['password'], ['knowledge']);
        $proof = new AuthenticationEvidence(
            ['webauthn', 'password'],
            ['possession', 'knowledge'],
        );

        $combined = $initial->merge($proof);

        self::assertSame(['password', 'webauthn'], $combined->methods);
        self::assertSame(['knowledge', 'possession'], $combined->capabilities);
        self::assertSame(['password'], $initial->methods);
        self::assertSame(['knowledge'], $initial->capabilities);
        self::assertSame(['webauthn', 'password'], $proof->methods);
    }

    public function testRepeatedProofAtTheEvidenceLimitDoesNotOverflow(): void
    {
        $methods = array_map(static fn(int $i): string => 'method.' . $i, range(1, 16));
        $evidence = new AuthenticationEvidence($methods, ['possession']);

        $combined = $evidence->merge($evidence);

        self::assertSame($methods, $combined->methods);
        self::assertSame(['possession'], $combined->capabilities);
    }

    public function testMergeRejectsTooManyDistinctMethods(): void
    {
        $methods = array_map(static fn(int $i): string => 'method.' . $i, range(1, 16));
        $evidence = new AuthenticationEvidence($methods);

        $this->expectException(\InvalidArgumentException::class);

        $evidence->merge(new AuthenticationEvidence(['extra']));
    }

    public function testMergeRejectsTooManyDistinctCapabilities(): void
    {
        $capabilities = array_map(static fn(int $i): string => 'capability.' . $i, range(1, 16));
        $evidence = new AuthenticationEvidence(['password'], $capabilities);

        $this->expectException(\InvalidArgumentException::class);

        $evidence->merge(new AuthenticationEvidence(['password'], ['extra']));
    }

    public function testRequiresAtLeastOneMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationEvidence([]);
    }

    public function testRejectsUnsafeIdentifiers(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AuthenticationEvidence(['otp email']);
    }

    public function testUnknownEvidenceIsExplicit(): void
    {
        $evidence = AuthenticationEvidence::unknown();

        self::assertSame(['unknown'], $evidence->methods);
        self::assertSame([], $evidence->capabilities);
    }
}
