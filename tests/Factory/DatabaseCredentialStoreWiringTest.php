<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\ConfigProvider;
use Componenta\Auth\Factory\DatabaseCodeStoreFactory;
use Componenta\Auth\Factory\DatabaseRefreshTokenStoreFactory;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Otp\CodeStoreInterface;
use Componenta\DI\ConfigKey as DiConfigKey;
use PHPUnit\Framework\TestCase;

final class DatabaseCredentialStoreWiringTest extends TestCase
{
    public function testBuiltInAtomicStoresAreTheDefaultBindings(): void
    {
        $config = (new ConfigProvider())();
        $dependencies = $config[DiConfigKey::DEPENDENCIES] ?? null;

        self::assertIsArray($dependencies);
        $factories = $dependencies[DiConfigKey::FACTORIES] ?? null;
        self::assertIsArray($factories);

        self::assertSame(
            DatabaseRefreshTokenStoreFactory::class,
            $factories[RefreshTokenStoreInterface::class] ?? null,
        );
        self::assertSame(
            DatabaseCodeStoreFactory::class,
            $factories[CodeStoreInterface::class] ?? null,
        );
    }

    public function testSecureCodeStoreDefaultRequiresAnApplicationSecret(): void
    {
        $config = (new ConfigProvider())();
        $auth = $config['auth'] ?? null;

        self::assertIsArray($auth);
        $otp = $auth['otp'] ?? null;

        self::assertIsArray($otp);
        self::assertSame('', $otp['hmacKey'] ?? null);
    }
}
