<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class AuthenticationMiddlewareRollbackTest extends TestCase
{
    public function testDownstreamExceptionRunsPendingCompensation(): void
    {
        $compensated = false;
        $middleware = new AuthenticationMiddleware(
            $this->extractor(),
            $this->authenticator($compensated),
            $this->createStub(\Componenta\Auth\Http\PayloadStorageInterface::class),
        );
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                throw new \RuntimeException('downstream failed');
            },
        );

        try {
            $middleware->process(new ServerRequestFixture(), $handler);
            self::fail('Downstream failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('downstream failed', $exception->getMessage());
        }

        self::assertTrue($compensated);
    }

    public function testMissingStorageRunsPendingCompensation(): void
    {
        $compensated = false;
        $middleware = new AuthenticationMiddleware(
            $this->extractor(),
            $this->authenticator($compensated),
        );
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                self::fail('Downstream must not run without storage.');
            },
        );

        try {
            $middleware->process(new ServerRequestFixture(), $handler);
            self::fail('Missing storage must fail.');
        } catch (\LogicException) {
        }

        self::assertTrue($compensated);
    }

    private function extractor(): PayloadExtractorInterface
    {
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());

        return $extractor;
    }

    private function authenticator(bool &$compensated): AuthenticatorInterface
    {
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturnCallback(
            static function (object $payload, ContextInterface $context) use (&$compensated): AuthenticationResult {
                $state = $context->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->onDiscard(static function () use (&$compensated): void {
                    $compensated = true;
                });

                return new AuthenticationResult(
                    new MiddlewareRollbackIdentityFixture(),
                    new \stdClass(),
                );
            },
        );

        return $authenticator;
    }
}

final class MiddlewareRollbackIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
