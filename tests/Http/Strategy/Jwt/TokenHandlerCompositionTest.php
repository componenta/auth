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
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenStoreInterface;
use Componenta\Auth\Http\Strategy\Jwt\SignerInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

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

    public function testMagicLinkTokenHandlerAppliesReferrerPolicyToDenial(): void
    {
        $headers = [];
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnCallback(
            static function (string $name, string|array $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = is_array($value) ? implode(', ', $value) : $value;

                return $response;
            },
        );
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $this->denyingAuthenticator(),
            $this->unusedTokenPair(),
            $this->deniedFactory($response),
            $this->createStub(ResponseFactoryInterface::class),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            queryParams: ['token' => self::MAGIC_TOKEN],
        )));
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
