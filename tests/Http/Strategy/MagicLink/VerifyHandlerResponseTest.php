<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class VerifyHandlerResponseTest extends TestCase
{
    private const string TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testMissingTokenResponseIsNonCacheableAndDoesNotLeakReferrer(): void
    {
        $headers = [];
        $response = $this->response($headers);
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(400)
            ->willReturn($response);

        $result = $this->handler(
            responseFactory: $factory,
        )->handle(new ServerRequestFixture());

        self::assertSame($response, $result);
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame('no-referrer', $headers['Referrer-Policy'] ?? null);
    }

    public function testDeniedVerificationDoesNotLeakReferrer(): void
    {
        $preflightHeaders = [];
        $preflight = $this->response($preflightHeaders);
        $deniedHeaders = [];
        $denied = $this->response($deniedHeaders);
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($preflight);
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult(new InvalidCredentials()),
        );
        $deniedFactory = $this->createStub(DeniedResponseFactoryInterface::class);
        $deniedFactory->method('create')->willReturn($denied);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');

        $result = $this->handler(
            authenticator: $authenticator,
            sessions: $sessions,
            deniedFactory: $deniedFactory,
            responseFactory: $factory,
        )->handle(new ServerRequestFixture(
            queryParams: ['token' => self::TOKEN],
        ));

        self::assertSame($denied, $result);
        self::assertSame('no-referrer', $deniedHeaders['Referrer-Policy'] ?? null);
    }

    public function testSuccessfulVerificationIsNonCacheableAndDoesNotLeakReferrer(): void
    {
        $identity = new VerifyHandlerIdentityFixture();
        $headers = [];
        $response = $this->response($headers);
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(new AuthenticationResult($identity));
        $sessions = $this->createStub(SessionManagerInterface::class);
        $sessions->method('create')->willReturn(self::session($identity->uuid));
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('remove')->willReturn($response);
        $storage->method('store')->willReturn($response);

        $result = $this->handler(
            authenticator: $authenticator,
            sessions: $sessions,
            storage: new ReplacingPayloadStorage($storage),
            responseFactory: $factory,
        )->handle(new ServerRequestFixture(
            queryParams: ['token' => self::TOKEN],
        ));

        self::assertSame($response, $result);
        self::assertSame('application/json', $headers['Content-Type'] ?? null);
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
        self::assertSame('no-referrer', $headers['Referrer-Policy'] ?? null);
    }

    private function handler(
        ?AuthenticatorInterface $authenticator = null,
        ?SessionManagerInterface $sessions = null,
        ?ReplacingPayloadStorage $storage = null,
        ?DeniedResponseFactoryInterface $deniedFactory = null,
        ?ResponseFactoryInterface $responseFactory = null,
    ): VerifyHandler {
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willReturn([]);

        return new VerifyHandler(
            new VerifyExtractor(),
            $authenticator ?? $this->createStub(AuthenticatorInterface::class),
            $sessions ?? $this->createStub(SessionManagerInterface::class),
            $storage ?? new ReplacingPayloadStorage(
                $this->createStub(PayloadStorageInterface::class),
            ),
            $deniedFactory ?? $this->createStub(DeniedResponseFactoryInterface::class),
            $responseFactory ?? $this->createStub(ResponseFactoryInterface::class),
            $attributes,
        );
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

    private static function session(UuidInterface $subjectId): Session
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            id: 'session-id',
            subjectId: $subjectId,
            expiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
            regenerateAt: $now->modify('+5 minutes'),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
        );
    }
}

final class VerifyHandlerIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
