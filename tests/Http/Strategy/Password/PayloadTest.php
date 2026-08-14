<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Password;

use Componenta\Auth\Http\Strategy\Password\Payload;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PayloadTest extends TestCase
{
    #[DataProvider('whitespaceIdentityProvider')]
    public function testIdentityRejectsLeadingAndTrailingWhitespace(string $identity): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Payload($identity, 'secret-password');
    }

    public function testBoundedIdentityWithoutWhitespaceIsAccepted(): void
    {
        $payload = new Payload('user@example.com', 'secret-password');

        self::assertSame('user@example.com', $payload->identity);
    }

    /** @return iterable<string, array{string}> */
    public static function whitespaceIdentityProvider(): iterable
    {
        yield 'leading whitespace' => [' user@example.com'];
        yield 'trailing whitespace' => ['user@example.com '];
    }
}
