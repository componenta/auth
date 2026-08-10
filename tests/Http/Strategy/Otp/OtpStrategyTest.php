<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Strategy\Otp\CodeStoreInterface;
use Componenta\Auth\Http\Strategy\Otp\CodeVerificationResult;
use Componenta\Auth\Http\Strategy\Otp\Denied\CodeExpired;
use Componenta\Auth\Http\Strategy\Otp\Denied\InvalidCode;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpPayload;
use Componenta\Auth\Http\Strategy\Otp\OtpStrategy;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class OtpStrategyTest extends TestCase
{
    public function testDelegatesVerificationToOneAtomicStoreCall(): void
    {
        $identity = new OtpIdentityFixture();
        $store = new CodeStoreFixture(CodeVerificationResult::verified('user-1'));
        $provider = new OtpUserProviderFixture($identity);
        $strategy = new OtpStrategy($provider, $store, new OtpConfig(maxAttempts: 3), new OtpClockFixture());
        $result = $strategy->attempt(new OtpPayload('mail@example.com', '123456'), new Context());

        self::assertSame($identity, $result->subject);
        self::assertSame(['mail@example.com', '123456', 1000, 3], $store->arguments);
    }

    public function testInvalidAtomicResultDoesNotLoadUser(): void
    {
        $store = new CodeStoreFixture(CodeVerificationResult::invalid());
        $provider = new OtpUserProviderFixture(null);
        $result = (new OtpStrategy($provider, $store, new OtpConfig(), new OtpClockFixture()))
            ->attempt(new OtpPayload('mail@example.com', 'old-code'), new Context());

        self::assertInstanceOf(InvalidCode::class, $result->subject);
        self::assertSame(0, $provider->findByIdCalls);
    }

    public function testExpiredResultRemainsDistinguishable(): void
    {
        $result = (new OtpStrategy(
            new OtpUserProviderFixture(null),
            new CodeStoreFixture(CodeVerificationResult::expired()),
            new OtpConfig(),
            new OtpClockFixture(),
        ))->attempt(new OtpPayload('mail@example.com', '123456'), new Context());

        self::assertInstanceOf(CodeExpired::class, $result->subject);
    }
}

final class CodeStoreFixture implements CodeStoreInterface
{
    /** @var array{string,string,int,int}|null */
    public ?array $arguments = null;
    public function __construct(private CodeVerificationResult $result) {}
    public function store(StoredCode $code): void {}
    public function invalidate(string $destination): void {}
    public function verifyAndConsume(string $destination, string $presentedCode, int $now, int $maxAttempts): CodeVerificationResult
    {
        $this->arguments = [$destination, $presentedCode, $now, $maxAttempts];
        return $this->result;
    }
}

final class OtpUserProviderFixture implements UserProviderInterface
{
    public int $findByIdCalls = 0;
    public function __construct(private ?IdentityInterface $identity) {}
    public function findByIdentity(string $identity): ?IdentityInterface { return null; }
    public function findById(string $userId): ?IdentityInterface
    {
        ++$this->findByIdCalls;
        return $this->identity;
    }
}

final class OtpIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}

final readonly class OtpClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable { return new DateTimeImmutable('@1000'); }
}
