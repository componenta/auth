<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\ConfigProvider;
use Componenta\Auth\Factory\DatabaseCodeStoreFactory;
use Componenta\Auth\Factory\DatabaseRefreshTokenStoreFactory;
use Componenta\Auth\Factory\OtpConfigFactory;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Otp\CodeStoreInterface;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\DI\ConfigKey as DiConfigKey;
use PHPUnit\Framework\TestCase;

final class DatabaseCredentialStoreWiringTest extends TestCase
{
    public function testBuiltInAtomicStoresAndOtpProfileAreDefaultBindings(): void
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
        self::assertSame(
            OtpConfigFactory::class,
            $factories[OtpConfig::class] ?? null,
        );
    }

    public function testSecureOtpDefaultsRequireSecretAndExposeHardenedProfile(): void
    {
        $config = (new ConfigProvider())();
        $auth = $config['auth'] ?? null;

        self::assertIsArray($auth);
        $otp = $auth['otp'] ?? null;

        self::assertIsArray($otp);
        self::assertSame('', $otp['hmacKey'] ?? null);
        self::assertSame(6, $otp['length'] ?? null);
        self::assertSame(300, $otp['ttl'] ?? null);
        self::assertSame(5, $otp['maxAttempts'] ?? null);
    }
}
