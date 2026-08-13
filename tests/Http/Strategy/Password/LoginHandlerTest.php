<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Password;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Password\LoginHandler;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LoginHandlerTest extends TestCase
{
    public function testSuccessfulLoginResponseIsNeverCacheable(): void
    {
        $identity = new LoginIdentityFixture();
        $authenticator = $this->authenticator($identity);
        $session = self::session($identity->uuid);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::once())
            ->method('create')
            ->with(
                self::callback(static fn(UuidInterface $uuid): bool =>
                    $uuid->equals($identity->uuid)),
                ['ip' => '', 'user_agent' => ''],
            )
            ->willReturn($session);
        $attributes = $this->attributes();
        $headers = [];
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(self::exactly(2))
            ->method('withHeader')
            ->willReturnCallback(
                static function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                    $headers[$name] = $value;

                    return $response;
                },
            );
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(
                self::isInstanceOf(ServerRequestInterface::class),
                $response,
                self::callback(static fn(object $payload): bool =>
                    $payload instanceof SessionPayload
                    && $payload->sessionId === $session->id),
            )
            ->willReturn($response);

        self::assertSame(
            $response,
            $this->handler(
                $authenticator,
                $sessions,
                $storage,
                $responses,
                $attributes,
            )->handle($this->request()),
        );
        self::assertSame([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $headers);
    }

    public function testResponseAllocationFailureCreatesNoSession(): void
    {
        $identity = new LoginIdentityFixture();
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $sessions->expects(self::never())->method('terminate');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willThrowException(
            new \RuntimeException('response allocation failed'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('response allocation failed');

        $this->handler(
            $this->authenticator($identity),
            $sessions,
            $storage,
            $responses,
            $this->attributes(),
        )->handle($this->request());
    }

    public function testStorageFailureRevokesRememberGrantAndTerminatesSession(): void
    {
        $identity = new LoginIdentityFixture();
        $session = self::session($identity->uuid);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::once())->method('create')->willReturn($session);
        $sessions->expects(self::once())->method('terminate')
            ->with($session->id);
        $remember = $this->createMock(RememberMeTokenManagerInterface::class);
        $remember->expects(self::once())->method('create')
            ->with(
                self::callback(static fn(UuidInterface $uuid): bool =>
                    $uuid->equals($identity->uuid)),
                $session->id,
            )
            ->willReturn(str_repeat('a', 64));
        $remember->expects(self::once())->method('revoke')
            ->with(str_repeat('a', 64));
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willThrowException(
            new \RuntimeException('transport failed'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('transport failed');

        $this->handler(
            $this->authenticator($identity),
            $sessions,
            $storage,
            $responses,
            $this->attributes(),
            $remember,
        )->handle($this->request(remember: true));
    }

    private function handler(
        AuthenticatorInterface $authenticator,
        SessionManagerInterface $sessions,
        PayloadStorageInterface $storage,
        ResponseFactoryInterface $responses,
        SessionAttributeExtractorInterface $attributes,
        ?RememberMeTokenManagerInterface $remember = null,
    ): LoginHandler {
        return new LoginHandler(
            new PasswordExtractor(),
            $authenticator,
            $sessions,
            $storage,
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
            $remember,
            $attributes,
        );
    }

    private function authenticator(IdentityInterface $identity): AuthenticatorInterface
    {
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity),
        );

        return $authenticator;
    }

    private function attributes(): SessionAttributeExtractorInterface
    {
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willReturn([
            'ip' => '',
            'user_agent' => '',
        ]);

        return $attributes;
    }

    private function request(bool $remember = false): ServerRequestInterface
    {
        return new ServerRequestFixture(parsedBody: [
            'email' => 'user@example.com',
            'password' => 'secret-password',
            'remember' => $remember,
        ]);
    }

    private static function session(UuidInterface $subjectId): SessionInterface
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            'session-id',
            $subjectId,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
    }
}

final class LoginIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
