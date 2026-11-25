<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\DeniedReasonInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DeniedReasonRedactionTest extends TestCase
{
    /** @return iterable<string, array{class-string<DeniedReasonInterface>}> */
    public static function denialTypes(): iterable
    {
        yield 'invalid credentials' => [InvalidCredentials::class];
        yield 'unauthorized' => [Unauthorized::class];
    }

    /** @param class-string<DeniedReasonInterface> $type */
    #[DataProvider('denialTypes')]
    public function testDiagnosticOutputDoesNotExposeAuditAttributes(string $type): void
    {
        $reason = new $type(['detail' => 'private-audit-value']);

        self::assertSame(['detail' => 'private-audit-value'], $reason->attributes);
        self::assertSame(
            ['code' => $reason->code],
            json_decode(json_encode($reason, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR),
        );

        ob_start();
        try {
            var_dump($reason);
            $debug = ob_get_contents();
        } finally {
            ob_end_clean();
        }

        self::assertIsString($debug);
        self::assertStringNotContainsString('private-audit-value', $debug);
        self::assertStringContainsString($reason->code, $debug);
    }
}
