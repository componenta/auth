<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\Middleware\InvalidPayloadMiddleware;
use Componenta\Auth\Http\Middleware\RequireAuthenticationMiddleware;
use Componenta\Auth\Http\Middleware\SessionGarbageCollectionMiddleware;
use Componenta\Auth\Http\Middleware\TouchSessionMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Session\SessionCleanupSchedulerInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class MiddlewareTraceTest extends TestCase
{
    public function testBuiltInMiddlewareDoesNotExposeDownstreamHandlerStateInTrace(): void
    {
        $request = new ServerRequestFixture(attributes: [
            IdentityInterface::class => new MiddlewareTraceIdentity(),
        ]);

        foreach ($this->middlewares() as $middleware) {
            $handler = new MiddlewareTraceThrowingHandler(
                'downstream-handler-secret-' . $middleware::class,
            );
            $exception = $this->capture(
                static fn() => $middleware->process($request, $handler),
            );

            self::assertInstanceOf(MiddlewareTraceFailure::class, $exception);
            self::assertStringNotContainsString(
                $handler->secret,
                var_export($exception->getTrace(), true),
                $middleware::class,
            );
        }
    }

    /** @return list<MiddlewareInterface> */
    private function middlewares(): array
    {
        return [
            new AuthenticationMiddleware(
                $this->createStub(PayloadExtractorInterface::class),
                $this->createStub(AuthenticatorInterface::class),
            ),
            new InvalidPayloadMiddleware(
                $this->createStub(ResponseFactoryInterface::class),
            ),
            new RequireAuthenticationMiddleware(
                $this->createStub(DeniedResponseFactoryInterface::class),
            ),
            new SessionGarbageCollectionMiddleware(
                $this->createStub(SessionCleanupSchedulerInterface::class),
            ),
            new TouchSessionMiddleware(
                $this->createStub(SessionManagerInterface::class),
            ),
        ];
    }

    private function capture(
        #[\SensitiveParameter]
        \Closure $callback,
    ): \Throwable {
        $previous = ini_get('zend.exception_ignore_args');
        self::assertIsString($previous);
        self::assertNotFalse(ini_set('zend.exception_ignore_args', '0'));
        $thrown = null;

        try {
            $callback();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }

        self::assertNotNull($thrown);

        return $thrown;
    }
}

final readonly class MiddlewareTraceThrowingHandler implements RequestHandlerInterface
{
    public function __construct(public string $secret) {}

    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        throw new MiddlewareTraceFailure('downstream failed');
    }
}

final class MiddlewareTraceFailure extends \RuntimeException
{
}

final class MiddlewareTraceIdentity implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
