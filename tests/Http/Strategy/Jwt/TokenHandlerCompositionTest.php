<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\MagicLink\TokenHandler as MagicLinkTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Otp\TokenHandler as OtpTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Password\TokenHandler as PasswordTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final class TokenHandlerCompositionTest extends TestCase
{
    private const string MAGIC_TOKEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testPasswordTokenHandlerUsesConfiguredAuthenticator(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $authenticator = $this->denyingAuthenticator();
        $denied = $this->deniedFactory($response);
        $handler = new PasswordTokenHandler(
            new PasswordExtractor(),
            $authenticator,
            self::uninitializedTokenPair(),
            $denied,
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
            self::uninitializedTokenPair(),
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

    public function testMagicLinkTokenHandlerUsesConfiguredAuthenticator(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(self::once())
            ->method('withHeader')
            ->with('Referrer-Policy', 'no-referrer')
            ->willReturnSelf();
        $handler = new MagicLinkTokenHandler(
            new VerifyExtractor(),
            $this->denyingAuthenticator(),
            self::uninitializedTokenPair(),
            $this->deniedFactory($response),
            $this->createStub(ResponseFactoryInterface::class),
        );

        self::assertSame($response, $handler->handle(new ServerRequestFixture(
            queryParams: ['token' => self::MAGIC_TOKEN],
        )));
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

    private static function uninitializedTokenPair(): TokenPairResponse
    {
        return (new \ReflectionClass(TokenPairResponse::class))
            ->newInstanceWithoutConstructor();
    }
}
