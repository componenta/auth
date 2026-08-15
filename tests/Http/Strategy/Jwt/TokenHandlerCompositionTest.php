<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\MagicLink\TokenHandler as MagicLinkTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Otp\TokenHandler as OtpTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Password\TokenHandler as PasswordTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationResult;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class TokenHandlerCompositionTest extends TestCase
{
    private const string MAGIC_TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testPasswordTokenHandlerUsesConfiguredAuthenticator(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $handler = new PasswordTokenHandler(
            new PasswordExtractor(),
            $this->denyingAuthenticator(),
            $this->unusedTokenPair(),
            $this->deniedFactory($response),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            parsedBody: [
                'email' => 'user@example.com',
                'password' => 'secret-password',
            ],
        )));
    }

    public function testOtpTokenHandlerUsesConfiguredAuthenticator(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $handler = new OtpTokenHandler(
            new OtpExtractor(new OtpConfig()),
            $this->denyingAuthenticator(),
            $this->unusedTokenPair(),
            $this->deniedFactory($response),
            $this->createStub(ResponseFactoryInterface::class),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            parsedBody: [
                'destination' => 'user@example.com',
                'code' => '123456',
            ],
        )));
    }

    public function testMagicLinkTokenHandlerHardensMissingTokenResponse(): void
    {
        $headers = [];
        $response = $this->response($headers);
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::once())
            ->method('createResponse')
            ->with(400)
            ->willReturn($response);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $authenticator,
            $this->unusedTokenPair(),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
        );

        self::assertSame($response, $handler->handle(
            new ServerRequestFixture(method: 'POST'),
        ));
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame('no-referrer', $headers['Referrer-Policy'] ?? null);
    }

    public function testMagicLinkTokenHandlerRejectsGet(): void
    {
        $headers = [];
        $response = $this->response($headers);
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::once())
            ->method('createResponse')
            ->with(405)
            ->willReturn($response);
        $authenticator = $this->createMock(
            AuthenticatorInterface::class,
        );
        $authenticator->expects(self::never())->method('attempt');
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $authenticator,
            $this->unusedTokenPair(),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
        );

        $result = $handler->handle(new ServerRequestFixture(
            method: 'GET',
            queryParams: ['token' => self::MAGIC_TOKEN],
        ));

        self::assertSame($response, $result);
        self::assertSame('POST', $headers['Allow'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame(
            'no-referrer',
            $headers['Referrer-Policy'] ?? null,
        );
    }

    public function testMagicLinkTokenHandlerAppliesReferrerPolicyToDenial(): void
    {
        $headers = [];
        $response = $this->response($headers);
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $this->denyingAuthenticator(),
            $this->unusedTokenPair(),
            $this->deniedFactory($response),
            $this->createStub(ResponseFactoryInterface::class),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            method: 'POST',
            parsedBody: ['token' => self::MAGIC_TOKEN],
        )));
        self::assertSame('no-referrer', $headers['Referrer-Policy'] ?? null);
    }

    public function testMagicLinkTokenHandlerHardensSuccessfulTokenResponse(): void
    {
        $identity = new TokenHandlerIdentityFixture();
        $headers = [];
        $response = $this->response($headers);
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(new AuthenticationResult($identity));
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $authenticator,
            $this->tokenPairForResponse($response),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $this->createStub(ResponseFactoryInterface::class),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            method: 'POST',
            parsedBody: ['token' => self::MAGIC_TOKEN],
        )));
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame('no-referrer', $headers['Referrer-Policy'] ?? null);
    }

    private function denyingAuthenticator(): AuthenticatorInterface
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::once())
            ->method('attempt')
            ->willReturn(new AuthenticationResult(new InvalidCredentials()));

        return $authenticator;
    }

    private function deniedFactory(
        ResponseInterface $response,
    ): DeniedResponseFactoryInterface {
        $factory = $this->createMock(DeniedResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('create')
            ->with(self::isInstanceOf(InvalidCredentials::class))
            ->willReturn($response);

        return $factory;
    }

    /** @param array<string, string> $headers */
    private function response(array &$headers): ResponseInterface
    {
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static fn(string $data): int => strlen($data),
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = $value;

                return $response;
            },
        );

        return $response;
    }

    private function tokenPairForResponse(ResponseInterface $response): TokenPairResponse
    {
        $clock = new TokenHandlerClockFixture();
        $config = new JwtConfig('https://issuer.example', 'componenta-api');
        $signer = $this->createStub(SignerInterface::class);
        $signer->method('sign')->willReturn('signed.access.token');
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);

        return new TokenPairResponse(
            $signer,
            new RefreshTokenManager(
                new TokenHandlerRefreshStoreFixture(),
                new RefreshTokenGenerator(),
                $config,
                $clock,
            ),
            $config,
            $responses,
            $clock,
        );
    }

    private function unusedTokenPair(): TokenPairResponse
    {
        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new DateTimeImmutable('@1000'));
        $config = new JwtConfig('https://issuer.example', 'componenta-api');

        return new TokenPairResponse(
            $this->createStub(SignerInterface::class),
            new RefreshTokenManager(
                $this->createStub(RefreshTokenStoreInterface::class),
                new RefreshTokenGenerator(),
                $config,
                $clock,
            ),
            $config,
            $this->createStub(ResponseFactoryInterface::class),
            $clock,
        );
    }
}

final class TokenHandlerRefreshStoreFixture implements RefreshTokenStoreInterface
{
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

    public function revoke(string $tokenId, int $revokedAt): void {}

    public function revokeAllForSubject(UuidInterface $subjectId, int $revokedAt): void {}
}

final class TokenHandlerIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final readonly class TokenHandlerClockFixture implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@1000');
    }
}
