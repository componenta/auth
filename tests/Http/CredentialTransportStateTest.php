<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CredentialTransportStateTest extends TestCase
{
    public function testClearWinsOverQueuedAndFutureCredentials(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $cleared = $this->createMock(ResponseInterface::class);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with($request, $response)
            ->willReturn($cleared);
        $state = new CredentialTransportState();
        $state->queue(new \stdClass());
        $state->clear();
        $state->queue(new \stdClass());

        self::assertSame($cleared, $state->apply($storage, $request, $response));
        self::assertTrue($state->cleared);
        self::assertFalse($state->empty);
        self::assertSame([], $state->payloads);
    }

    public function testQueuedPayloadIsCommittedWhenCredentialsWereNotCleared(): void
    {
        $payload = new \stdClass();
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $stored = $this->createMock(ResponseInterface::class);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::once())->method('store')
            ->with($request, $response, $payload)
            ->willReturn($stored);
        $storage->expects(self::never())->method('remove');
        $state = new CredentialTransportState();
        self::assertTrue($state->empty);
        $state->queue($payload);

        self::assertFalse($state->empty);
        self::assertSame([$payload], $state->payloads);
        self::assertSame($stored, $state->apply($storage, $request, $response));
    }
}
