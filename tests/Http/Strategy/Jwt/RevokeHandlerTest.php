<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Jwt\RevokeHandler;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class RevokeHandlerTest extends TestCase
{
    private const string TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testValidRefreshBearerIsRevokedAndResponseIsSemanticallyEmpty(): void
    {
        $store = new RevokeHandlerStoreFixture();
        $headers = ['Content-Type' => 'application/json'];
        $response = $this->response($headers);
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'refresh_token' => self::TOKEN,
        ]);

        $result = $this->handler($store, $factory)->handle($request);

        self::assertSame($response, $result);
        self::assertSame([self::TOKEN, 1000], $store->revoked);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertArrayNotHasKey('Content-Type', $headers);
    }

    public function testMissingRefreshBearerIsIdempotentAndDoesNotRevokeAnything(): void
    {
        $store = new RevokeHandlerStoreFixture();
        $headers = [];
        $response = $this->response($headers);
        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory->method('createResponse')->willReturn($response);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([]);

        self::assertSame(
            $response,
            $this->handler($store, $factory)->handle($request),
        );
        self::assertNull($store->revoked);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertArrayNotHasKey('Content-Type', $headers);
    }

    private function handler(
        RevokeHandlerStoreFixture $store,
        ResponseFactoryInterface $responseFactory,
    ): RevokeHandler {
        return new RevokeHandler(
            new RefreshTokenManager(
                $store,
                new RefreshTokenGenerator(),
                new JwtConfig('https://issuer.example', 'componenta-api'),
                new RevokeHandlerClockFixture(),
            ),
            $responseFactory,
        );
    }

    /** @param array<string, string> $headers */
    private function response(array &$headers): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = $value;

                return $response;
            },
        );
        $response->method('withoutHeader')->willReturnCallback(
            static function (string $name) use (&$headers, $response): ResponseInterface {
                unset($headers[$name]);

                return $response;
            },
        );

        return $response;
    }
}

final class RevokeHandlerStoreFixture implements RefreshTokenStoreInterface
{
    /** @var array{string, int}|null */
    public ?array $revoked = null;

    public function storeInitial(RefreshToken $token): void {}

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

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void {}
}

final readonly class RevokeHandlerClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
