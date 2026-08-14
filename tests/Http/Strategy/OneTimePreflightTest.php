<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler as MagicLinkVerifyHandler;
use Componenta\Auth\Http\Strategy\Otp\OtpConfig;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\VerifyHandler as OtpVerifyHandler;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;

final class OneTimePreflightTest extends TestCase
{
    private const string MAGIC_TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function testOtpAttributeFailureHappensBeforeCredentialConsumption(): void
    {
        $failure = new \RuntimeException('attribute extraction failed');
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willThrowException($failure);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::never())->method('createResponse');
        $handler = new OtpVerifyHandler(
            new OtpExtractor(new OtpConfig()),
            $authenticator,
            $sessions,
            $this->createStub(PayloadStorageInterface::class),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
            $attributes,
        );

        $this->expectExceptionObject($failure);
        $handler->handle($this->otpRequest());
    }

    public function testOtpResponseAllocationFailureHappensBeforeCredentialConsumption(): void
    {
        $failure = new \RuntimeException('response allocation failed');
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willReturn([]);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willThrowException($failure);
        $handler = new OtpVerifyHandler(
            new OtpExtractor(new OtpConfig()),
            $authenticator,
            $sessions,
            $this->createStub(PayloadStorageInterface::class),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
            $attributes,
        );

        $this->expectExceptionObject($failure);
        $handler->handle($this->otpRequest());
    }

    public function testMagicLinkAttributeFailureHappensBeforeCredentialConsumption(): void
    {
        $failure = new \RuntimeException('attribute extraction failed');
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willThrowException($failure);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $responses = $this->createMock(ResponseFactoryInterface::class);
        $responses->expects(self::never())->method('createResponse');
        $handler = new MagicLinkVerifyHandler(
            new VerifyExtractor(),
            $authenticator,
            $sessions,
            new ReplacingPayloadStorage(
                $this->createStub(PayloadStorageInterface::class),
            ),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
            $attributes,
        );

        $this->expectExceptionObject($failure);
        $handler->handle($this->magicLinkRequest());
    }

    public function testMagicLinkResponseAllocationFailureHappensBeforeCredentialConsumption(): void
    {
        $failure = new \RuntimeException('response allocation failed');
        $attributes = $this->createStub(SessionAttributeExtractorInterface::class);
        $attributes->method('extract')->willReturn([]);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willThrowException($failure);
        $handler = new MagicLinkVerifyHandler(
            new VerifyExtractor(),
            $authenticator,
            $sessions,
            new ReplacingPayloadStorage(
                $this->createStub(PayloadStorageInterface::class),
            ),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $responses,
            $attributes,
        );

        $this->expectExceptionObject($failure);
        $handler->handle($this->magicLinkRequest());
    }

    private function otpRequest(): ServerRequestFixture
    {
        return new ServerRequestFixture(parsedBody: [
            'destination' => 'user@example.com',
            'code' => '123456',
        ]);
    }

    private function magicLinkRequest(): ServerRequestFixture
    {
        return new ServerRequestFixture(queryParams: [
            'token' => self::MAGIC_TOKEN,
        ]);
    }
}
