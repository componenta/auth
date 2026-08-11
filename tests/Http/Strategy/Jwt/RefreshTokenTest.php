<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class RefreshTokenTest extends TestCase
{
    private const string TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string FAMILY =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    public function testBearerAndFamilyIdentifiersAreRedactedFromDebugAndJson(): void
    {
        $token = new RefreshToken(
            id: self::TOKEN,
            subjectId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            familyId: self::FAMILY,
            expiresAt: 2000,
        );

        $debug = $token->__debugInfo();

        self::assertSame('[REDACTED]', $debug['id']);
        self::assertSame('[REDACTED]', $debug['familyId']);
        self::assertSame(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            $debug['subjectId'],
        );

        $json = json_encode($token, JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString(self::TOKEN, $json);
        self::assertStringNotContainsString(self::FAMILY, $json);
        self::assertStringContainsString('[REDACTED]', $json);
    }
}
