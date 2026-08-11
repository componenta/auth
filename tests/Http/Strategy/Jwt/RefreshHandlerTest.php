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

final class RefreshHandlerTest extends TestCase
{
    private const string PRESENTED = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testRevokesRotatedSuccessorWhenSubjectNoLongerExists(): void
    {
        $store = new RefreshHandlerStoreFixture();
        $provider = $this->createMock(JwtUserProviderInterface::class);
        $provider->expects(self::once())
            ->method('findByUuid')
            ->with(self::isInstanceOf(UuidInterface::class))
            ->willReturn(null);

        $this->assertInvalidProviderResultRevokesSuccessor($store, $provider);
    }

    public function testRevokesRotatedSuccessorWhenProviderReturnsDifferentUuid(): void
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

        $this->assertInvalidProviderResultRevokesSuccessor($store, $provider);
    }

    private function assertInvalidProviderResultRevokesSuccessor(
        RefreshHandlerStoreFixture $store,
        JwtUserProviderInterface $provider,
    ): void {
        $clock = new RefreshHandlerClockFixture();
        $config = new JwtConfig('https://issuer.example', 'componenta-api', refreshTtl: 60);
        $manager = new RefreshTokenManager(
            $store,
            new RefreshTokenGenerator(),
            $config,
            $clock,
        );
        $signer = $this->createMock(SignerInterface::class);
        $signer->expects(self::never())->method('sign');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $deniedFactory = $this->createMock(DeniedResponseFactoryInterface::class);
        $deniedFactory->expects(self::once())
            ->method('create')
            ->with(self::isInstanceOf(InvalidRefreshToken::class))
            ->willReturn($response);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn(['refresh_token' => self::PRESENTED]);
        $handler = new RefreshHandler(
            $manager,
            $provider,
            $signer,
            $config,
            $deniedFactory,
            $this->createStub(ResponseFactoryInterface::class),
            $clock,
        );

        self::assertSame($response, $handler->handle($request));
        self::assertSame([$store->successor, 1000], $store->revoked);
    }
}

final class RefreshHandlerStoreFixture implements RefreshTokenStoreInterface
{
    public ?string $successor = null;
    /** @var array{string, int}|null */
    public ?array $revoked = null;

    public function storeInitial(RefreshToken $token): void {}

    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        $this->successor = $successorTokenId;

        return RefreshTokenRotationResult::rotated(new RefreshToken(
            $successorTokenId,
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
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

final readonly class RefreshHandlerClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
