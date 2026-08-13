<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\DeniedResponseFactoryInterface;
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

final class RefreshHandlerPostRotationProviderTest extends TestCase
{
    private const string PRESENTED =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testAccountDisappearingAfterPreflightRevokesSuccessor(): void
    {
        $store = new PostRotationStoreFixture();
        $provider = new PostRotationProviderFixture(disappearAfterPreflight: true);
        $denied = $this->createStub(ResponseInterface::class);
        $denied->method('withHeader')->willReturnSelf();
        $deniedFactory = $this->createStub(DeniedResponseFactoryInterface::class);
        $deniedFactory->method('create')->willReturn($denied);

        $result = $this->handler($store, $provider, $deniedFactory)
            ->handle($this->request());

        self::assertSame($denied, $result);
        self::assertSame(2, $provider->calls);
        self::assertSame(1, $store->rotateCalls);
        self::assertSame($store->successor, $store->revokedToken);
    }

    public function testProviderFailureAfterRotationRevokesSuccessor(): void
    {
        $store = new PostRotationStoreFixture();
        $provider = new PostRotationProviderFixture(throwAfterPreflight: true);
        $deniedFactory = $this->createStub(DeniedResponseFactoryInterface::class);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('provider changed while rotating');

        try {
            $this->handler($store, $provider, $deniedFactory)
                ->handle($this->request());
        } finally {
            self::assertSame(2, $provider->calls);
            self::assertSame(1, $store->rotateCalls);
            self::assertSame($store->successor, $store->revokedToken);
        }
    }

    private function handler(
        PostRotationStoreFixture $store,
        JwtUserProviderInterface $provider,
        DeniedResponseFactoryInterface $deniedFactory,
    ): RefreshHandler {
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $response = $this->createStub(ResponseInterface::class);
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);
        $config = new JwtConfig(
            'https://issuer.example',
            'componenta-api',
            refreshTtl: 60,
        );

        return new RefreshHandler(
            new RefreshTokenManager(
                $store,
                new RefreshTokenGenerator(),
                $config,
                new PostRotationClockFixture(),
            ),
            $provider,
            $signer,
            $config,
            $deniedFactory,
            $responseFactory,
            new PostRotationClockFixture(),
        );
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

final class PostRotationStoreFixture implements RefreshTokenStoreInterface
{
    public int $rotateCalls = 0;
    public ?string $successor = null;
    public ?string $revokedToken = null;
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
        return $tokenId === RefreshHandlerPostRotationProviderTest::PRESENTED
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
            str_repeat('b', 64),
            $successorExpiresAt,
        ));
    }

    public function revoke(string $tokenId, int $revokedAt): void
    {
        $this->revokedToken = $tokenId;
    }

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void {}
}

final class PostRotationProviderFixture implements JwtUserProviderInterface
{
    public int $calls = 0;
    private IdentityInterface $identity;

    public function __construct(
        private bool $disappearAfterPreflight = false,
        private bool $throwAfterPreflight = false,
    ) {
        $this->identity = new PostRotationIdentityFixture();
    }

    public function findByUuid(UuidInterface $uuid): ?IdentityInterface
    {
        ++$this->calls;

        if ($this->calls > 1) {
            if ($this->throwAfterPreflight) {
                throw new \RuntimeException('provider changed while rotating');
            }

            if ($this->disappearAfterPreflight) {
                return null;
            }
        }

        return $this->identity;
    }
}

final class PostRotationIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final readonly class PostRotationClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
