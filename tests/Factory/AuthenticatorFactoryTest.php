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
use Componenta\Config\Config;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class AuthenticatorFactoryTest extends TestCase
{
    public function testPreservesConfiguredStrategyOrder(): void
    {
        $calls = [];
        $identity = new FactoryIdentityFixture();
        $container = new FactoryContainerFixture([
            ConfigKey::CONFIG => new Config(['auth' => ['strategies' => ['first', 'second'], 'events' => false]]),
            'first' => new OrderedStrategyFixture('first', $calls, new AuthenticationResult(new DeniedReason('denied'))),
            'second' => new OrderedStrategyFixture('second', $calls, new AuthenticationResult($identity)),
        ]);

        $result = (new AuthenticatorFactory())($container)->attempt(new \stdClass(), new Context());

        self::assertSame($identity, $result->subject);
        self::assertSame(['first', 'second'], $calls);
    }

    public function testRejectsDuplicateStrategyServices(): void
    {
        $this->expectException(AuthenticatorConfigurationException::class);
        $calls = [];
        (new AuthenticatorFactory())(new FactoryContainerFixture([
            ConfigKey::CONFIG => new Config(['auth' => ['strategies' => ['same', 'same'], 'events' => false]]),
            'same' => new OrderedStrategyFixture('same', $calls, new AuthenticationResult(new DeniedReason('x'))),
        ]));
    }
}

final class FactoryContainerFixture implements ContainerInterface
{
    /** @param array<string, mixed> $services */
    public function __construct(private array $services) {}
    public function get(string $id): mixed { return $this->services[$id] ?? throw new \RuntimeException($id); }
    public function has(string $id): bool { return array_key_exists($id, $this->services); }
}

final class OrderedStrategyFixture implements AuthenticationStrategyInterface
{
    /** @param list<string> $calls */
    public function __construct(
        private string $name,
        private array &$calls,
        private AuthenticationResult $result,
    ) {}
    public function supports(object $payload, ContextInterface $context): bool { return true; }
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $this->calls[] = $this->name;
        return $this->result;
    }
}

final class FactoryIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}
