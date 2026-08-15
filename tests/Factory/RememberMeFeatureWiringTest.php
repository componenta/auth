<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigKey;
use Componenta\Auth\ConfigProvider;
use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Factory\LoginHandlerFactory;
use Componenta\Auth\Factory\PriorityListenerProviderFactory;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\RememberMe\RememberMeRegenerationListener;
use Componenta\Auth\RememberMe\RememberMeTerminationListener;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Config\Config;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final class RememberMeFeatureWiringTest extends TestCase
{
    public function testSecureDefaultKeepsRememberMeDisabled(): void
    {
        $config = (new ConfigProvider())();
        $auth = $config[ConfigKey::AUTH] ?? null;

        self::assertIsArray($auth);
        $rememberMe = $auth[ConfigKey::REMEMBER_ME] ?? null;
        self::assertIsArray($rememberMe);
        self::assertFalse($rememberMe[ConfigKey::ENABLED] ?? null);
        self::assertSame([], $config[ConfigKey::LISTENERS]);
    }

    public function testDisabledRememberMeDoesNotResolveLifecycleListeners(): void
    {
        $container = new TrackingContainerFixture([
            ConfigKey::CONFIG => new Config([
                ConfigKey::AUTH => [
                    ConfigKey::REMEMBER_ME => [ConfigKey::ENABLED => false],
                ],
                ConfigKey::LISTENERS => [],
            ]),
        ]);

        $provider = (new PriorityListenerProviderFactory())($container);

        self::assertSame([], iterator_to_array($provider->provideFor(
            new SessionRegenerated(
                'old-session',
                'new-session',
                new DateTimeImmutable('@1'),
            ),
        )));
        self::assertNotContains(
            RememberMeTerminationListener::class,
            $container->getCalls,
        );
        self::assertNotContains(
            RememberMeRegenerationListener::class,
            $container->getCalls,
        );
    }

    public function testEnabledRememberMeAutomaticallyWiresBothLifecycleListeners(): void
    {
        $tokens = $this->createStub(RememberMeTokenManagerInterface::class);
        $termination = new RememberMeTerminationListener($tokens);
        $regeneration = new RememberMeRegenerationListener($tokens);
        $container = new TrackingContainerFixture([
            ConfigKey::CONFIG => new Config([
                ConfigKey::AUTH => [
                    ConfigKey::REMEMBER_ME => [ConfigKey::ENABLED => true],
                ],
                ConfigKey::LISTENERS => [],
            ]),
            RememberMeTerminationListener::class => $termination,
            RememberMeRegenerationListener::class => $regeneration,
        ]);
        $timestamp = new DateTimeImmutable('@1');
        $provider = (new PriorityListenerProviderFactory())($container);

        self::assertSame(
            [$regeneration],
            iterator_to_array($provider->provideFor(
                new SessionRegenerated('old-session', 'new-session', $timestamp),
            )),
        );
        self::assertSame(
            [$termination],
            iterator_to_array($provider->provideFor(
                new AllSessionsTerminated(
                    Uuid::fromString(
                        '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
                    ),
                    null,
                    $timestamp,
                ),
            )),
        );
    }

    public function testLoginFactoryResolvesRememberManagerWhenFeatureIsEnabled(): void
    {
        $container = new TrackingContainerFixture([
            ConfigKey::CONFIG => new Config([
                ConfigKey::AUTH => [
                    ConfigKey::REMEMBER_ME => [ConfigKey::ENABLED => true],
                ],
            ]),
            PasswordExtractor::class => new PasswordExtractor(),
            AuthenticatorInterface::class => $this->createStub(AuthenticatorInterface::class),
            SessionManagerInterface::class => $this->createStub(SessionManagerInterface::class),
            PayloadStorageInterface::class => $this->createStub(PayloadStorageInterface::class),
            DeniedResponseFactoryInterface::class => $this->createStub(DeniedResponseFactoryInterface::class),
            ResponseFactoryInterface::class => $this->createStub(ResponseFactoryInterface::class),
            SessionAttributeExtractorInterface::class => $this->createStub(SessionAttributeExtractorInterface::class),
            RememberMeTokenManagerInterface::class => $this->createStub(RememberMeTokenManagerInterface::class),
        ]);

        (new LoginHandlerFactory())($container);

        self::assertContains(
            RememberMeTokenManagerInterface::class,
            $container->getCalls,
        );
    }

    public function testLoginFactoryDoesNotResolveRememberManagerWhenFeatureIsDisabled(): void
    {
        $container = new TrackingContainerFixture([
            ConfigKey::CONFIG => new Config([
                ConfigKey::AUTH => [
                    ConfigKey::REMEMBER_ME => [ConfigKey::ENABLED => false],
                ],
            ]),
            PasswordExtractor::class => new PasswordExtractor(),
            AuthenticatorInterface::class => $this->createStub(AuthenticatorInterface::class),
            SessionManagerInterface::class => $this->createStub(SessionManagerInterface::class),
            PayloadStorageInterface::class => $this->createStub(PayloadStorageInterface::class),
            DeniedResponseFactoryInterface::class => $this->createStub(DeniedResponseFactoryInterface::class),
            ResponseFactoryInterface::class => $this->createStub(ResponseFactoryInterface::class),
            SessionAttributeExtractorInterface::class => $this->createStub(SessionAttributeExtractorInterface::class),
        ]);

        (new LoginHandlerFactory())($container);

        self::assertNotContains(
            RememberMeTokenManagerInterface::class,
            $container->getCalls,
        );
    }
}

final class TrackingContainerFixture implements ContainerInterface
{
    /** @var list<string> */
    public array $getCalls = [];

    /** @param array<string, mixed> $services */
    public function __construct(private array $services) {}

    #[\Override]
    public function get(string $id): mixed
    {
        $this->getCalls[] = $id;

        return $this->services[$id] ?? throw new \RuntimeException($id);
    }

    #[\Override]
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->services);
    }
}
