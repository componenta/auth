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

    #[DataProvider('invalidTtls')]
    public function testRejectsOutOfBandTtlBeyondTenMinutes(int $ttl): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new OtpConfig(ttl: $ttl);
    }

    public function testGeneratorSupportsMaximumLengthWithoutIntegerOverflow(): void
    {
        $code = (new CodeGenerator(new OtpConfig(length: 18)))->generate();

        self::assertMatchesRegularExpression('/\A[0-9]{18}\z/D', $code);
    }

    /** @return iterable<string, array{int}> */
    public static function invalidLengths(): iterable
    {
        yield 'below OOB minimum' => [5];
        yield 'too short' => [3];
        yield 'too long' => [19];
        yield 'unbounded' => [100];
    }

    /** @return iterable<string, array{int}> */
    public static function invalidTtls(): iterable
    {
        yield 'zero' => [0];
        yield 'over ten minutes' => [601];
        yield 'one day' => [86400];
    }
}
