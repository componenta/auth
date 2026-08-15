<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\Http\Middleware\SessionGarbageCollectionMiddleware;
use Componenta\Auth\Session\SessionCleanupSchedulerInterface;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class SessionGarbageCollectionMiddlewareTest extends TestCase
{
    public function testSchedulerFailureDoesNotReplaceSuccessfulApplicationResponse(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $scheduler = $this->createMock(SessionCleanupSchedulerInterface::class);
        $scheduler->expects(self::once())
            ->method('schedule')
            ->willThrowException(new \RuntimeException('queue unavailable'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                'Unable to schedule session cleanup.',
                self::callback(static fn(array $context): bool =>
                    ($context['exception'] ?? null) instanceof \RuntimeException),
            );
        $handler = new CallbackRequestHandler(
            static fn(): ResponseInterface => $response,
        );

        self::assertSame(
            $response,
            (new SessionGarbageCollectionMiddleware($scheduler, 1, $logger))
                ->process(new ServerRequestFixture(), $handler),
        );
    }

    public function testInvalidLotteryIsRejectedAtConstruction(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new SessionGarbageCollectionMiddleware(
            $this->createStub(SessionCleanupSchedulerInterface::class),
            0,
        );
    }
}
