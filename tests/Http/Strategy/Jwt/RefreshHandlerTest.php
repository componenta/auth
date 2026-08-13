<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\JwtUserProviderInterface;
use Componenta\Auth\Http\Strategy\Jwt\RefreshHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class RefreshHandlerTest extends TestCase
{
    public const string PRESENTED_FOR_FIXTURE = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string PRESENTED = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testMissingSubjectIsRevokedBeforeRotation(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->createMock(JwtUserProviderInterface::class);
        $provider->expects(self::once())
            ->method('findByUuid')
            ->with(self::isInstanceOf(UuidInterface::class))
            ->willReturn(null);

        $response = $this->assertInvalidProviderResult($store, $provider);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertSame(0, $store->rotateCalls);
        self::assertSame([self::PRESENTED, 1000], $store->revoked);
    }

    public function testProviderCannotSubstituteDifferentUuidBeforeRotation(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->createMock(JwtUserProviderInterface::class);
        $provider->expects(self::once())
            ->method('findByUuid')
            ->willReturn(new class implements IdentityInterface {
                public UuidInterface $uuid {
                    get => Uuid::fromString(
                        '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
                    );
                }
            });

        $this->assertInvalidProviderResult($store, $provider);

        self::assertSame(0, $store->rotateCalls);
        self::assertSame([self::PRESENTED, 1000], $store->revoked);
    }

    public function testProviderFailureLeavesPresentedRefreshRetryable(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->createMock(JwtUserProviderInterface::class);
        $provider->method('findByUuid')->willThrowException(
            new \RuntimeException('provider unavailable'),
        );
        $signer = $this->createMock(SignerInterface::class);
        $signer->expects(self::never())->method('sign');
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())->method('createResponse');

        $handler = $this->handler($store, $provider, $signer, $responseFactory);

        try {
            $handler->handle($this->request());
            self::fail('Provider failure must escape to the application error boundary.');
        } catch (\RuntimeException $exception) {
            self::assertSame('provider unavailable', $exception->getMessage());
        }

        self::assertSame(0, $store->rotateCalls);
        self::assertNull($store->revoked);
        self::assertSame(self::PRESENTED, $store->preflightToken);
    }

    public function testSigningFailureLeavesPresentedRefreshRetryable(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->provider(new RefreshHandlerIdentityFixture());
        $signer = $this->createMock(SignerInterface::class);
        $signer->method('sign')->willThrowException(
            new \RuntimeException('signer unavailable'),
        );
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())->method('createResponse');

        $handler = $this->handler($store, $provider, $signer, $responseFactory);

        try {
            $handler->handle($this->request());
            self::fail('Signing failure must escape to the application error boundary.');
        } catch (\RuntimeException $exception) {
            self::assertSame('signer unavailable', $exception->getMessage());
        }

        self::assertSame(0, $store->rotateCalls);
        self::assertNull($store->revoked);
    }

    public function testResponseAllocationFailureLeavesPresentedRefreshRetryable(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->provider(new RefreshHandlerIdentityFixture());
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willThrowException(
            new \RuntimeException('response allocation failed'),
        );

        $handler = $this->handler($store, $provider, $signer, $responseFactory);

        try {
            $handler->handle($this->request());
            self::fail('Response allocation failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('response allocation failed', $exception->getMessage());
        }

        self::assertSame(0, $store->rotateCalls);
        self::assertNull($store->revoked);
    }

    public function testPostRotationResponseFailureRevokesUnknownSuccessor(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->provider(new RefreshHandlerIdentityFixture());
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $body = $this->createMock(StreamInterface::class);
        $body->method('write')->willThrowException(
            new \RuntimeException('stream failed'),
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($body);
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);

        $handler = $this->handler($store, $provider, $signer, $responseFactory);

        try {
            $handler->handle($this->request());
            self::fail('Response stream failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('stream failed', $exception->getMessage());
        }

        self::assertSame(1, $store->rotateCalls);
        self::assertSame([$store->successor, 1000], $store->revoked);
    }

    private function assertInvalidProviderResult(
        RefreshHandlerStoreFixture $store,
        JwtUserProviderInterface $provider,
    ): ResponseInterface {
        $signer = $this->createMock(SignerInterface::class);
        $signer->expects(self::never())->method('sign');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $deniedFactory = $this->createMock(DeniedResponseFactoryInterface::class);
        $deniedFactory->expects(self::once())
            ->method('create')
            ->with(self::isInstanceOf(InvalidRefreshToken::class))
            ->willReturn($response);
        $handler = new RefreshHandler(
            $this->manager($store),
            $provider,
            $signer,
            $this->config(),
            $deniedFactory,
            $this->createStub(ResponseFactoryInterface::class),
            new RefreshHandlerClockFixture(),
        );

        return $handler->handle($this->request());
    }

    private function handler(
        RefreshHandlerStoreFixture $store,
        JwtUserProviderInterface $provider,
        SignerInterface $signer,
        ResponseFactoryInterface $responseFactory,
    ): RefreshHandler {
        return new RefreshHandler(
            $this->manager($store),
            $provider,
            $signer,
            $this->config(),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responseFactory,
            new RefreshHandlerClockFixture(),
        );
    }

    private function manager(RefreshHandlerStoreFixture $store): RefreshTokenManager
    {
        return new RefreshTokenManager(
            $store,
            new RefreshTokenGenerator(),
            $this->config(),
            new RefreshHandlerClockFixture(),
        );
    }

    private function config(): JwtConfig
    {
        return new JwtConfig(
            'https://issuer.example',
            'componenta-api',
            refreshTtl: 60,
        );
    }

    private function provider(IdentityInterface $identity): JwtUserProviderInterface
    {
        $provider = $this->createStub(JwtUserProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);

        return $provider;
    }

    private function request(): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'refresh_token' => self::PRESENTED,
        ]);

        return $request;
    }
}

final class RefreshHandlerStoreFixture implements RefreshTokenStoreInterface
{
    public ?string $successor = null;
    /** @var array{string, int}|null */
    public ?array $revoked = null;
    public int $rotateCalls = 0;
    public ?string $preflightToken = null;

    private UuidInterface $subjectId;

    public function __construct()
    {
        $this->subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    public function storeInitial(RefreshToken $token): void {}

    public function findActiveSubject(string $tokenId, int $now): ?UuidInterface
    {
        $this->preflightToken = $tokenId;

        return $tokenId === RefreshHandlerTest::PRESENTED_FOR_FIXTURE
            ? $this->subjectId
            : null;
    }

    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        ++$this->rotateCalls;
        $this->successor = $successorTokenId;

        return RefreshTokenRotationResult::rotated(new RefreshToken(
            $successorTokenId,
            $this->subjectId,
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            $successorExpiresAt,
        ));
    }

    public function revoke(string $tokenId, int $revokedAt): void
    {
        $this->revoked = [$tokenId, $revokedAt];
    }

    public function revokeAllForSubject(UuidInterface $subjectId, int $revokedAt): void {}
}

final class RefreshHandlerIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final readonly class RefreshHandlerClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
