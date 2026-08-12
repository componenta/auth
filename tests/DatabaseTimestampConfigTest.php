<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Token\TokenConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DatabaseTimestampConfigTest extends TestCase
{
    /** @return iterable<string, array{0: \Closure(): object}> */
    public static function unsafeConfigProvider(): iterable
    {
        yield 'session' => [
            static fn(): object => new DatabaseSessionManagerConfig(
                dateFormat: 'd/m/Y H:i:s',
            ),
        ];
        yield 'remember-me' => [
            static fn(): object => new DatabaseRememberMeTokenManagerConfig(
                dateFormat: 'd/m/Y H:i:s',
            ),
        ];
        yield 'one-time token' => [
            static fn(): object => new TokenConfig(
                table: 'tokens',
                purpose: 'test',
                dateFormat: 'd/m/Y H:i:s',
            ),
        ];
    }

    #[DataProvider('unsafeConfigProvider')]
    public function testDatabaseCredentialStoresRejectNonSortableTimestampFormats(
        \Closure $factory,
    ): void {
        $this->expectException(\InvalidArgumentException::class);

        $factory();
    }
}
