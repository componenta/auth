<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ConfigKey;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Exception\AuthenticatorConfigurationException;
use Componenta\Auth\Factory\AuthenticatorFactory;
use Componenta\Auth\Http\Strategy\RememberMe\RememberMeStrategy;
use Componenta\Auth\Http\Strategy\Session\UserProviderInterface;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Config\Config;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class AuthenticatorFactoryTest extends TestCase
{
    public function testPreservesConfiguredStrategyOrderForExplicitSoftFailure(): void
    {
        $recorder = new StrategyCallRecorder();
        $identity = new FactoryIdentityFixture();
        $container = new FactoryContainerFixture([
            ConfigKey::CONFIG => new Config(['auth' => ['strategies' => ['first', 'second'], 'events' => false]]),
            'first' => new OrderedStrategyFixture('first', $recorder, new AuthenticationResult(
                subject: new DeniedReason('denied'),
                continueOnFailure: true,
            )),
            'second' => new OrderedStrategyFixture('second', $recorder, new AuthenticationResult($identity)),
        ]);

        $result = (new AuthenticatorFactory())($container)->attempt(new \stdClass(), new Context());

        self::assertSame($identity, $result->subject);
        self::assertSame(['first', 'second'], $recorder->calls);
    }

    public function testRejectsDuplicateStrategyServices(): void
    {
        $this->expectException(AuthenticatorConfigurationException::class);
        $recorder = new StrategyCallRecorder();
        (new AuthenticatorFactory())(new FactoryContainerFixture([
            ConfigKey::CONFIG => new Config(['auth' => ['strategies' => ['same', 'same'], 'events' => false]]),
            'same' => new OrderedStrategyFixture('same', $recorder, new AuthenticationResult(new DeniedReason('x'))),
        ]));
    }

    public function testRejectsBuiltInRememberMeStrategyWhenFeatureIsDisabled(): void
    {
        $rememberMe = new RememberMeStrategy(
            $this->createStub(RememberMeTokenManagerInterface::class),
            $this->createStub(SessionManagerInterface::class),
            $this->createStub(UserProviderInterface::class),
        );
        $container = new FactoryContainerFixture([
            ConfigKey::CONFIG => new Config([
                ConfigKey::AUTH => [
                    ConfigKey::STRATEGIES => ['remember'],
                    ConfigKey::EVENTS => false,
                    ConfigKey::REMEMBER_ME => [ConfigKey::ENABLED => false],
                ],
            ]),
            'remember' => $rememberMe,
        ]);

        $this->expectException(AuthenticatorConfigurationException::class);
        $this->expectExceptionMessage('auth.rememberMe.enabled=true');

        (new AuthenticatorFactory())($container);
    }
}

final class FactoryContainerFixture implements ContainerInterface
{
    /** @param array<string, mixed> $services */
    public function __construct(private array $services) {}
    public function get(string $id): mixed { return $this->services[$id] ?? throw new \RuntimeException($id); }
    public function has(string $id): bool { return array_key_exists($id, $this->services); }
}

final class StrategyCallRecorder
{
    /** @var list<string> */
    public array $calls = [];
}

final class OrderedStrategyFixture implements AuthenticationStrategyInterface
{
    public function __construct(
        private string $name,
        private StrategyCallRecorder $recorder,
        private AuthenticationResult $result,
    ) {}
    public function supports(object $payload, ContextInterface $context): bool { return true; }
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $this->recorder->calls[] = $this->name;
        return $this->result;
    }
}

final class FactoryIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}
