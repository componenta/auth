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
        $response = $this->responseStub();
        $cleared = $this->responseStub();
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
    }

    public function testQueuedPayloadUsesItsOwnStorage(): void
    {
        $payloadA = new \stdClass();
        $payloadB = new \stdClass();
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $afterA = $this->responseStub();
        $afterB = $this->responseStub();
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

        self::assertSame($afterB, $state->apply($request, $response));
    }

    public function testClearRemovesEveryRegisteredTransport(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $afterA = $this->responseStub();
        $afterB = $this->responseStub();
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

    public function testDiscardQueuedCancelsPendingCredentialWritesAndRunsCompensation(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $compensated = false;
        $state->onDiscard(static function () use (&$compensated): void {
            $compensated = true;
        });

        $state->discardQueued();

        self::assertTrue($compensated);
        self::assertTrue($state->empty);
        self::assertSame($response, $state->apply($request, $response));
    }

    public function testTransportFailureCompensatesUnpublishedDurableState(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willThrowException(
            new \RuntimeException('transport failed'),
        );
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $compensated = false;
        $state->onDiscard(static function () use (&$compensated): void {
            $compensated = true;
        });

        try {
            $state->apply($request, $response);
            self::fail('Transport failure must escape.');
        } catch (\RuntimeException $exception) {
            self::assertSame('transport failed', $exception->getMessage());
        }

        self::assertTrue($compensated);
        self::assertTrue($state->empty);
    }

    public function testSuccessfulApplyCommitsDiscardCallbacks(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $mutated = $this->responseStub();
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willReturn($mutated);
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());
        $discarded = false;
        $state->onDiscard(static function () use (&$discarded): void {
            $discarded = true;
        });

        self::assertSame($mutated, $state->apply($request, $response));
        $state->discardQueued();

        self::assertFalse($discarded);
        self::assertTrue($state->empty);
    }

    public function testCredentialMutationForcesNoStoreHeaders(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $response = $this->responseStub();
        $mutated = $this->createStub(ResponseInterface::class);
        $headers = [];
        $mutated->method('withHeader')->willReturnCallback(
            static function (string $name, string $value) use (&$headers, $mutated): ResponseInterface {
                $headers[$name] = $value;

                return $mutated;
            },
        );
        $storage = $this->createStub(PayloadStorageInterface::class);
        $storage->method('store')->willReturn($mutated);
        $state = new CredentialTransportState();
        $state->queue($storage, new \stdClass());

        self::assertSame($mutated, $state->apply($request, $response));
        self::assertSame('no-store', $headers['Cache-Control'] ?? null);
        self::assertSame('no-cache', $headers['Pragma'] ?? null);
    }

    private function responseStub(): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();

        return $response;
    }
}
