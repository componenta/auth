<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Password;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Strategy\Password\PasswordAwareInterface;
use Componenta\Auth\Http\Strategy\Password\PasswordStrategy;
use Componenta\Auth\Http\Strategy\Password\Payload;
use Componenta\Auth\Http\Strategy\Password\UserProviderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Componenta\Stdlib\PasswordHasherInterface;
use Componenta\Stdlib\PasswordVerifierInterface;
use PHPUnit\Framework\TestCase;

final class PasswordStrategyTest extends TestCase
{
    public function testProviderReceivesIdentityStringNotCredentialPayload(): void
    {
        $identity = new PasswordIdentityFixture();
        $provider = new PasswordProviderFixture($identity);
        $strategy = new PasswordStrategy($provider, new PasswordHasherFixture(), 'dummy');
        $result = $strategy->attempt(new Payload('user@example.com', 'secret'), new Context());

        self::assertSame('user@example.com', $provider->providedIdentity);
        self::assertSame($identity, $result->subject);
    }
}

final class PasswordProviderFixture implements UserProviderInterface
{
    public ?string $providedIdentity = null;
    public function __construct(private ?PasswordIdentityFixture $identity) {}
    public function findByIdentity(string $identity): null|(IdentityInterface&PasswordAwareInterface)
    {
        $this->providedIdentity = $identity;
        return $this->identity;
    }
}

final class PasswordIdentityFixture implements IdentityInterface, PasswordAwareInterface
{
    public string $hash { get => 'hash'; }
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}

final class PasswordHasherFixture implements PasswordHasherInterface, PasswordVerifierInterface
{
    public function hash(string $password): string { return 'dummy'; }
    public function verify(string $password, string $hash): bool { return $password === 'secret' && $hash === 'hash'; }
}
