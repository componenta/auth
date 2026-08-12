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
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $cleared = $this->createStub(ResponseInterface::class);
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with($request, $response)
            ->willReturn($cleared);
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $state->clear($storage);
        $state->queue($storage, new \stdClass());

        self::assertSame($cleared, $state->apply($request, $response));
        self::assertTrue($state->cleared);
        self::assertFalse($state->empty);
        self::assertSame([], $state->payloads);
    }

    public function testQueuedPayloadUsesItsOwnStorage(): void
    {
        $payloadA = new \stdClass();
        $payloadB = new \stdClass();
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $afterA = $this->createStub(ResponseInterface::class);
        $afterB = $this->createStub(ResponseInterface::class);
        $storageA = $this->createMock(PayloadStorageInterface::class);
        $storageB = $this->createMock(PayloadStorageInterface::class);
        $storageA->expects(self::once())->method('store')
            ->with($request, $response, $payloadA)
            ->willReturn($afterA);
        $storageB->expects(self::once())->method('store')
            ->with($request, $afterA, $payloadB)
            ->willReturn($afterB);
        $state = new CredentialTransportState();
        $state->queue($storageA, $payloadA);
        $state->queue($storageB, $payloadB);

        self::assertSame([$payloadA, $payloadB], $state->payloads);
        self::assertSame($afterB, $state->apply($request, $response));
    }

    public function testClearRemovesEveryRegisteredTransport(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $afterA = $this->createStub(ResponseInterface::class);
        $afterB = $this->createStub(ResponseInterface::class);
        $storageA = $this->createMock(PayloadStorageInterface::class);
        $storageB = $this->createMock(PayloadStorageInterface::class);
        $storageA->expects(self::once())->method('remove')
            ->with($request, $response)
            ->willReturn($afterA);
        $storageB->expects(self::once())->method('remove')
            ->with($request, $afterA)
            ->willReturn($afterB);
        $state = new CredentialTransportState();
        $state->register($storageA);
        $state->clear($storageB);

        self::assertSame($afterB, $state->apply($request, $response));
    }
}
