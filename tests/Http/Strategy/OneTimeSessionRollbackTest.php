<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler as MagicLinkVerifyHandler;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\VerifyHandler as OtpVerifyHandler;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class OneTimeSessionRollbackTest extends TestCase
{
    public function testOtpStorageFailureTerminatesUnpublishedSession(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'destination' => 'login@example.com',
            'code' => '123456',
        ]);

        $handler = new OtpVerifyHandler(
            new OtpExtractor(new OtpConfig()),
            $this->authenticator(),
            $this->sessionManager(),
            $this->failingStorage(),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $this->responseFactory(),
            $this->attributeExtractor(),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('credential transport failed');
        $handler->handle($request);
    }

    public function testMagicLinkStorageFailureTerminatesUnpublishedSession(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([
            'token' => str_repeat('a', 64),
        ]);

        $handler = new MagicLinkVerifyHandler(
            new VerifyExtractor(),
            $this->authenticator(),
            $this->sessionManager(),
            new ReplacingPayloadStorage($this->failingStorage()),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $this->responseFactory(),
            $this->attributeExtractor(),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('credential transport failed');
        $handler->handle($request);
    }

    private function authenticator(): AuthenticatorInterface
    {
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult(new OneTimeIdentityFixture()),
        );

        return $authenticator;
    }

    private function sessionManager(): SessionManagerInterface
    {
        $session = new Session(
            id: 'session-id',
            subjectId: OneTimeIdentityFixture::uuid(),
            expiresAt: new DateTimeImmutable('@2000'),
            absoluteExpiresAt: new DateTimeImmutable('@3000'),
            regenerateAt: new DateTimeImmutable('@1500'),
            replacedBy: null,
            createdAt: new DateTimeImmutable('@1000'),
            lastActiveAt: new DateTimeImmutable('@1000'),
        );
        $manager = $this->createMock(SessionManagerInterface::class);
        $manager->expects(self::once())->method('create')->willReturn($session);
        $manager->expects(self::once())->method('terminate')->with('session-id');

        return $manager;
    }

    private function failingStorage(): PayloadStorageInterface
    {
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willThrowException(
            new \RuntimeException('credential transport failed'),
        );

        return $storage;
    }

    private function responseFactory(): ResponseFactoryInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory->method('createResponse')->willReturn($response);

        return $factory;
    }

    private function attributeExtractor(): SessionAttributeExtractorInterface
    {
        $extractor = $this->createStub(SessionAttributeExtractorInterface::class);
        $extractor->method('extract')->willReturn([]);

        return $extractor;
    }
}

final class OneTimeIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => self::uuid();
    }

    public static function uuid(): UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
