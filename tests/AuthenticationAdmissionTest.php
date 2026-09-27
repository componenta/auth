<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class AuthenticationAdmissionTest extends TestCase
{
    public function testReloadsCanonicalIdentityOnEveryAdmission(): void
    {
        $id = (new UuidFactory())->generate();
        $first = self::identity($id);
        $updated = self::identity($id);
        $provider = $this->createMock(IdentityProviderInterface::class);
        $provider->expects(self::exactly(2))->method('findByUuid')->with($id)->willReturnOnConsecutiveCalls($first, $updated);
        $guard = $this->createMock(AuthenticationGuardInterface::class);
        $evidence = new AuthenticationEvidence(['password']);
        $seen = [];
        $guard->expects(self::exactly(2))->method('check')->willReturnCallback(
            static function ($identity, $proof) use (&$seen, $evidence) {
                self::assertSame($evidence, $proof);
                $seen[] = $identity;
                return null;
            },
        );
        $admission = new AuthenticationAdmission($provider, $guard);
        self::assertSame($first, $admission->check($id, $evidence));
        self::assertSame($updated, $admission->check($id, $evidence));
        self::assertSame([$first, $updated], $seen);
    }

    public function testDeletedOrMismatchedIdentityCannotReachGuard(): void
    {
        $provider = $this->createMock(IdentityProviderInterface::class);
        $provider->expects(self::exactly(2))->method('findByUuid')->willReturnOnConsecutiveCalls(null, self::identity((new UuidFactory())->generate()));
        $guard = $this->createMock(AuthenticationGuardInterface::class);
        $guard->expects(self::never())->method('check');
        $admission = new AuthenticationAdmission($provider, $guard);
        for ($i = 0; $i < 2; ++$i) {
            self::assertInstanceOf(InvalidCredentials::class, $admission->check((new UuidFactory())->generate(), new AuthenticationEvidence(['password'])));
        }
    }

    public function testReturnsDenialWithoutConvertingItToSuccess(): void
    {
        $identity = self::identity((new UuidFactory())->generate());
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $denial = new DeniedReason('user_disabled');
        $guard->method('check')->willReturn($denial);
        self::assertSame($denial, (new AuthenticationAdmission($provider, $guard))->check($identity->uuid, new AuthenticationEvidence(['webauthn'])));
    }

    public function testGuardFailureDoesNotBecomeAnAllowDecision(): void
    {
        $identity = self::identity((new UuidFactory())->generate());
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $guard->method('check')->willThrowException(new \RuntimeException('guard unavailable'));
        $this->expectException(\RuntimeException::class);
        (new AuthenticationAdmission($provider, $guard))->check($identity->uuid, new AuthenticationEvidence(['password']));
    }

    private static function identity(UuidInterface $id): IdentityInterface
    {
        return new readonly class($id) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
    }
}
