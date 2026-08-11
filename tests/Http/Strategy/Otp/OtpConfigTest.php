<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Http\Strategy\Otp\CodeGenerator;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OtpConfigTest extends TestCase
{
    #[DataProvider('invalidLengths')]
    public function testRejectsUnsupportedCodeLengths(int $length): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new OtpConfig(length: $length);
    }

    public function testGeneratorSupportsMaximumLengthWithoutIntegerOverflow(): void
    {
        $code = (new CodeGenerator(new OtpConfig(length: 18)))->generate();

        self::assertMatchesRegularExpression('/\A[0-9]{18}\z/D', $code);
    }

    /** @return iterable<string, array{int}> */
    public static function invalidLengths(): iterable
    {
        yield 'too short' => [3];
        yield 'too long' => [19];
        yield 'unbounded' => [100];
    }
}
