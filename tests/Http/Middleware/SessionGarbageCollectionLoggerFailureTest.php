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

final class SessionGarbageCollectionLoggerFailureTest extends TestCase
{
    public function testLoggerFailureDoesNotReplaceSuccessfulApplicationResponse(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $scheduler = $this->createStub(SessionCleanupSchedulerInterface::class);
        $scheduler->method('schedule')->willThrowException(
            new \RuntimeException('queue unavailable'),
        );
        $logger = $this->createStub(LoggerInterface::class);
        $logger->method('warning')->willThrowException(
            new \RuntimeException('logger unavailable'),
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
}
