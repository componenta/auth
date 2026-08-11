<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigProvider;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Factory\AuthenticatorFactory;
use Componenta\Auth\Factory\EventDispatcherFactory;
use Componenta\Auth\Factory\PriorityListenerProviderFactory;
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

    public function testCompiledCompositionResolvesThroughSupportedDiGenerationModel(): void
    {
        if (self::builderHasMethod('compileGeneratedEntryResolver')) {
            self::assertDi2GeneratedResolverComposition();

            return;
        }

        self::assertDi3CompiledCacheComposition();
    }

    private static function assertDi2GeneratedResolverComposition(): void
    {
        $file = sys_get_temp_dir()
            . '/componenta-auth-di-'
            . bin2hex(random_bytes(8))
            . '.php';
        $fingerprint = 'componenta-auth-v2-test';

        try {
            $builder = self::builder();
            $compile = new \ReflectionMethod(
                ContainerBuilder::class,
                'compileGeneratedEntryResolver',
            );
            $compile->invoke(
                $builder,
                [
                    AuthenticatorFactory::class,
                    EventDispatcherFactory::class,
                    PriorityListenerProviderFactory::class,
                ],
                $file,
                null,
                'Componenta\\Auth\\Tests\\GeneratedDi',
                $fingerprint,
            );

            $compiledBuilder = self::builder();
            $install = new \ReflectionMethod(
                ContainerBuilder::class,
                'useGeneratedEntryResolver',
            );
            $install->invoke($compiledBuilder, $file, $fingerprint);
            $container = $compiledBuilder->build();

            self::assertInstanceOf(
                AuthenticatorInterface::class,
                $container->get(AuthenticatorInterface::class),
            );
        } finally {
            @unlink($file);
        }
    }

    private static function assertDi3CompiledCacheComposition(): void
    {
        if (
            !self::builderHasMethod('compileFactories')
            || !self::builderHasMethod('normalizeDependencies')
            || !defined(ContainerBuilder::class . '::CACHE_VERSION')
            || !defined(ContainerBuilder::class . '::CACHE_VALIDATED_KEY')
        ) {
            throw new \LogicException(
                'The installed Componenta DI version exposes no supported compilation model.',
            );
        }

        $configuration = self::configuration();
        $dependencies = $configuration[DiConfigKey::DEPENDENCIES] ?? null;

        if (!is_array($dependencies)) {
            throw new \LogicException('The DI dependencies configuration must be an array.');
        }

        $normalize = new \ReflectionMethod(
            ContainerBuilder::class,
            'normalizeDependencies',
        );
        $normalized = $normalize->invoke(null, $dependencies);

        if (!is_array($normalized)) {
            throw new \LogicException('Normalized DI dependencies must be an array.');
        }

        $version = constant(ContainerBuilder::class . '::CACHE_VERSION');
        $validatedKey = constant(
            ContainerBuilder::class . '::CACHE_VALIDATED_KEY',
        );

        if (!is_int($version) || !is_string($validatedKey)) {
            throw new \LogicException('The DI cache contract is invalid.');
        }

        $configure = new \ReflectionMethod(
            ContainerBuilder::class,
            'configureFromCache',
        );
        $builder = $configure->invoke(
            null,
            new Config($configuration),
            [
                'version' => $version,
                $validatedKey => true,
                DiConfigKey::DEPENDENCIES => $normalized,
            ],
        );

        if (!$builder instanceof ContainerBuilder) {
            throw new \LogicException('DI cache configuration did not return a builder.');
        }

        self::assertInstanceOf(
            AuthenticatorInterface::class,
            $builder->build()->get(AuthenticatorInterface::class),
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
    private static function builderHasMethod(string $method): bool
    {
        return (new \ReflectionClass(ContainerBuilder::class))->hasMethod($method);
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
