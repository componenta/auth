<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class StoredCodeTest extends TestCase
{
    public function testPlaintextCodeIsRedactedFromDebugAndJson(): void
    {
        $code = new StoredCode(
            subjectId: Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            code: '123456',
            destination: 'mail@example.com',
            expiresAt: 2000,
        );

        self::assertSame('[REDACTED]', $code->__debugInfo()['code']);
        self::assertStringNotContainsString(
            '123456',
            json_encode($code, JSON_THROW_ON_ERROR),
        );
        self::assertSame('123456', $code->code);
    }
}
