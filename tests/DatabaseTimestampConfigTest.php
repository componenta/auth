<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Token\TokenConfig;
use PHPUnit\Framework\TestCase;

final class DatabaseTimestampConfigTest extends TestCase
{
    public function testCredentialTimestampFormatsAreFixedInternalContracts(): void
    {
        self::assertSame(
            DatabaseSessionManagerConfig::DATE_FORMAT,
            (new DatabaseSessionManagerConfig())->dateFormat,
        );
        self::assertSame(
            DatabaseRememberMeTokenManagerConfig::DATE_FORMAT,
            (new DatabaseRememberMeTokenManagerConfig())->dateFormat,
        );
        self::assertSame(
            TokenConfig::DATE_FORMAT,
            (new TokenConfig('tokens', 'test'))->dateFormat,
        );
    }
}
