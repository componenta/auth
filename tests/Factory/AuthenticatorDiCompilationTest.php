<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigProvider;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Config\Config;
use Componenta\DI\ConfigKey as DiConfigKey;
use Componenta\DI\ContainerBuilder;
use PHPUnit\Framework\TestCase;

final class AuthenticatorDiCompilationTest extends TestCase
{
    public function testRuntimeCompositionResolvesThroughComponentaDi(): void
    {
        $container = self::builder()->build();

        self::assertInstanceOf(
            AuthenticatorInterface::class,
            $container->get(AuthenticatorInterface::class),
        );
    }

    public function testCachedCompositionResolvesThroughPublicDiContract(): void
    {
        $configuration = self::configuration();
        $dependencies = $configuration[DiConfigKey::DEPENDENCIES] ?? null;

        self::assertIsArray($dependencies);

        $container = ContainerBuilder::configureFromCache(
            new Config($configuration),
            ContainerBuilder::normalizeDependencies($dependencies),
        )->build();

        self::assertInstanceOf(
            AuthenticatorInterface::class,
            $container->get(AuthenticatorInterface::class),
        );
    }

    private static function builder(): ContainerBuilder
    {
        return ContainerBuilder::configure(new Config(self::configuration()));
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
