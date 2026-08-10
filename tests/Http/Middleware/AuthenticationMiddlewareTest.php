<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthenticationMiddlewareTest extends TestCase
{
    public function testDownstreamCredentialClearCancelsPendingRotation(): void
    {
        $pendingCredential = new \stdClass();
        $payload = new \stdClass();
        $attributes = [];
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('withAttribute')->willReturnCallback(
            static function (string $name, mixed $value) use (&$attributes, $request): ServerRequestInterface {
                $attributes[$name] = $value;
                return $request;
            },
        );
        $request->method('getAttribute')->willReturnCallback(
            static function (string $name, mixed $default = null) use (&$attributes): mixed {
                return $attributes[$name] ?? $default;
            },
        );

        $extractor = $this->createMock(PayloadExtractorInterface::class);
        $extractor->method('extract')->with($request)->willReturn($payload);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('attempt')->with($payload, self::isInstanceOf(ContextInterface::class))
            ->willReturn(new AuthenticationResult(new DeniedReason('fixture'), $pendingCredential));

        $response = $this->createMock(ResponseInterface::class);
        $clearedResponse = $this->createMock(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturnCallback(
            static function (ServerRequestInterface $handledRequest) use ($response): ResponseInterface {
                $state = $handledRequest->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->clear();
                return $response;
            },
        );

        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with($request, $response)
            ->willReturn($clearedResponse);

        $result = (new AuthenticationMiddleware($extractor, $authenticator, $storage))
            ->process($request, $handler);

        self::assertSame($clearedResponse, $result);
    }
}
