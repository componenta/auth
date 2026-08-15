<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\BearerCredential;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class TokenPairResponseBearerContractTest extends TestCase
{
    public function testCustomSignerCannotIssueAnAccessTokenTheBearerTransportRejects(): void
    {
        $store = new TokenPairBearerStoreFixture();
        $config = new JwtConfig('https://issuer.example', 'componenta-api');
        $clock = new TokenPairBearerClockFixture();
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn(
            str_repeat('a', BearerCredential::MAX_LENGTH + 1),
        );
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())->method('createResponse');
        $tokenPair = $this->tokenPair($store, $signer, $responseFactory, $config, $clock);

        $this->expectException(\InvalidArgumentException::class);

        try {
            $tokenPair->create(new TokenPairBearerIdentityFixture());
        } finally {
            self::assertFalse($store->stored);
        }
    }

    public function testResponseAllocationFailureHappensBeforeRefreshIssuance(): void
    {
        $store = new TokenPairBearerStoreFixture();
        $config = new JwtConfig('https://issuer.example', 'componenta-api');
        $clock = new TokenPairBearerClockFixture();
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willThrowException(
            new \RuntimeException('response allocation failed'),
        );
        $tokenPair = $this->tokenPair($store, $signer, $responseFactory, $config, $clock);

        try {
            $tokenPair->create(new TokenPairBearerIdentityFixture());
            self::fail('Response allocation failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('response allocation failed', $exception->getMessage());
        }

        self::assertFalse($store->stored);
        self::assertNull($store->revoked);
    }

    public function testPostIssuanceResponseFailureRevokesUnknownRefreshFamily(): void
    {
        $store = new TokenPairBearerStoreFixture();
        $config = new JwtConfig('https://issuer.example', 'componenta-api');
        $clock = new TokenPairBearerClockFixture();
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $body = $this->createStub(StreamInterface::class);
        $body->method('write')->willThrowException(
            new \RuntimeException('stream failed'),
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($body);
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);
        $tokenPair = $this->tokenPair($store, $signer, $responseFactory, $config, $clock);

        try {
            $tokenPair->create(new TokenPairBearerIdentityFixture());
            self::fail('Response stream failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('stream failed', $exception->getMessage());
        }

        self::assertTrue($store->stored);
        self::assertNotNull($store->storedToken);
        self::assertSame([$store->storedToken->id, 1000], $store->revoked);
    }

    private function tokenPair(
        TokenPairBearerStoreFixture $store,
        SignerInterface $signer,
        ResponseFactoryInterface $responseFactory,
        JwtConfig $config,
        ClockInterface $clock,
    ): TokenPairResponse {
        return new TokenPairResponse(
            $signer,
            new RefreshTokenManager(
                $store,
                new RefreshTokenGenerator(),
                $config,
                $clock,
            ),
            $config,
            $responseFactory,
            $clock,
        );
    }
}

final class TokenPairBearerStoreFixture implements RefreshTokenStoreInterface
{
    public bool $stored = false;
    public ?RefreshToken $storedToken = null;
    /** @var array{string, int}|null */
    public ?array $revoked = null;

    public function storeInitial(RefreshToken $token): void
    {
        $this->stored = true;
        $this->storedToken = $token;
    }

    public function findActiveSubject(string $tokenId, int $now): ?UuidInterface
    {
        return null;
    }

    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        return RefreshTokenRotationResult::invalid();
    }

    public function revoke(string $tokenId, int $revokedAt): void
    {
        $this->revoked = [$tokenId, $revokedAt];
    }

    public function revokeAllForSubject(UuidInterface $subjectId, int $revokedAt): void {}
}

final class TokenPairBearerIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final readonly class TokenPairBearerClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
