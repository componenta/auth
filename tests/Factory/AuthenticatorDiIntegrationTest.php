<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigProvider;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Config\ConfigKey as DiConfigKey;
use PHPUnit\Framework\TestCase;

final class AuthenticatorDiIntegrationTest extends TestCase
{
    public function testRuntimeCompositionResolvesThroughComponentaDi(): void
    {
        foreach (['development', 'production'] as $mode) {
            $composition = (new \Componenta\Config\ConfigFactory())->create(
                new \Componenta\Config\Environment(['APP_ENV' => $mode]),
                static fn (): array => self::configuration(),
            );
            $container = (new \Componenta\DI\ContainerFactory())->create($composition->config, $composition->dependencies);
            self::assertInstanceOf(AuthenticatorInterface::class, $container->get(AuthenticatorInterface::class));
        }
    }

    /** @return array<string, mixed> */
    private static function configuration(): array
    {
        /** @var array<string, mixed> $config */
        $config = (new ConfigProvider())();
        $auth = $config['auth'] ?? null;

        if (!is_array($auth)) {
            throw new \LogicException('The auth configuration must be an array.');
        }

        $rememberMe = $auth['rememberMe'] ?? null;

        if (!is_array($rememberMe)) {
            throw new \LogicException('The remember-me configuration must be an array.');
        }

        $dependencies = $config[DiConfigKey::DEPENDENCIES] ?? null;

        if (!is_array($dependencies)) {
            throw new \LogicException('The DI dependencies configuration must be an array.');
        }

        /** @var array<string, mixed> $dependencies */
        $invokables = $dependencies[DiConfigKey::INVOKABLES] ?? [];

        if (!is_array($invokables)) {
            throw new \LogicException('The DI invokables configuration must be an array.');
        }

        $invokables[] = DiAuthenticationStrategyFixture::class;
        $dependencies[DiConfigKey::INVOKABLES] = $invokables;
        $config[DiConfigKey::DEPENDENCIES] = $dependencies;

        $auth['strategies'] = [DiAuthenticationStrategyFixture::class];
        $auth['events'] = true;
        $rememberMe['enabled'] = false;
        $auth['rememberMe'] = $rememberMe;
        $config['auth'] = $auth;

        return $config;
    }
}

final readonly class DiAuthenticationStrategyFixture implements AuthenticationStrategyInterface
{
    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return true;
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        return new AuthenticationResult(new DeniedReason('test_denied'));
    }
}
