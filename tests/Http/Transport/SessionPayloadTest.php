<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Transport;

use Componenta\Auth\Http\Transport\SessionPayload;
use PHPUnit\Framework\TestCase;

final class SessionPayloadTest extends TestCase
{
    public function testCredentialsAreRedactedFromDebugAndJsonRepresentations(): void
    {
        $payload = new SessionPayload(
            sessionId: 'session-secret',
            rememberMeToken: 'remember-secret',
        );

        self::assertSame([
            'sessionId' => '[REDACTED]',
            'rememberMeToken' => '[REDACTED]',
        ], $payload->__debugInfo());

        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('session-secret', $json);
        self::assertStringNotContainsString('remember-secret', $json);
        self::assertSame(
            '{"sessionId":"[REDACTED]","rememberMeToken":"[REDACTED]"}',
            $json,
        );
    }

    public function testAbsentCredentialsRemainNullInRedactedRepresentation(): void
    {
        $payload = new SessionPayload();

        self::assertSame([
            'sessionId' => null,
            'rememberMeToken' => null,
        ], $payload->__debugInfo());
    }
}
