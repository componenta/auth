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
