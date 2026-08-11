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
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity),
        );
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
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willReturn([
            'ip' => '',
            'user_agent' => '',
        ]);
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
        $request = new ServerRequestFixture(parsedBody: [
            'email' => 'user@example.com',
            'password' => 'secret-password',
        ]);

        self::assertSame(
            $response,
            (new LoginHandler(
                new PasswordExtractor(),
                $authenticator,
                $sessions,
                $storage,
                $this->createStub(DeniedResponseFactoryInterface::class),
                $responses,
                attributeExtractor: $attributes,
            ))->handle($request),
        );
        self::assertSame([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $headers);
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
