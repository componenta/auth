<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\ConfigProvider;
use Componenta\Auth\Factory\CompensatingRememberMeStrategyFactory;
use Componenta\Auth\Http\Strategy\RememberMe\CompensatingRememberMeStrategy;
use Componenta\DI\ConfigKey as DiConfigKey;
use PHPUnit\Framework\TestCase;

final class CompensatingRememberMeStrategyWiringTest extends TestCase
{
    public function testDiscardSafeRememberStrategyHasAFactoryBinding(): void
    {
        $config = (new ConfigProvider())();
        $dependencies = $config[DiConfigKey::DEPENDENCIES] ?? null;

        self::assertIsArray($dependencies);
        $factories = $dependencies[DiConfigKey::FACTORIES] ?? null;
        self::assertIsArray($factories);
        self::assertSame(
            CompensatingRememberMeStrategyFactory::class,
            $factories[CompensatingRememberMeStrategy::class] ?? null,
        );
    }
}
