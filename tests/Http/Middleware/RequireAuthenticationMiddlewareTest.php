<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Denied\Unauthorized;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Middleware\RequireAuthenticationMiddleware;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class RequireAuthenticationMiddlewareTest extends TestCase
{
    public function testAuthenticatedRequestContinuesWithoutCreatingDenial(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $factory = $this->createMock(DeniedResponseFactoryInterface::class);
        $factory->expects(self::never())->method('create');
        $request = new ServerRequestFixture(attributes: [
            IdentityInterface::class => new RequireAuthenticationIdentityFixture(),
        ]);
        $handler = new CallbackRequestHandler(
            static fn(): ResponseInterface => $response,
        );

        self::assertSame(
            $response,
            (new RequireAuthenticationMiddleware($factory))->process($request, $handler),
        );
    }

    public function testExistingDenialIsPreservedAndDownstreamDoesNotRun(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $reason = new DeniedReason('rate_limited');
        $factory = $this->createMock(DeniedResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('create')
            ->with($reason)
            ->willReturn($response);
        $request = new ServerRequestFixture(attributes: [
            DeniedReasonInterface::class => $reason,
        ]);
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                self::fail('Unauthenticated request must not reach downstream handler.');
            },
        );

        self::assertSame(
            $response,
            (new RequireAuthenticationMiddleware($factory))->process($request, $handler),
        );
    }

    public function testMissingAuthenticationStateProducesUnauthorizedDenial(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $factory = $this->createMock(DeniedResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('create')
            ->with(self::isInstanceOf(Unauthorized::class))
            ->willReturn($response);
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                self::fail('Unauthenticated request must not reach downstream handler.');
            },
        );

        self::assertSame(
            $response,
            (new RequireAuthenticationMiddleware($factory))->process(
                new ServerRequestFixture(),
                $handler,
            ),
        );
    }
}

final class RequireAuthenticationIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
