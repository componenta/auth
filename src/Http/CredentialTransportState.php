<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Request-scoped accumulator with terminal clear-over-store precedence. */
final class CredentialTransportState
{
    /** @var array<int, PayloadStorageInterface> */
    private array $storages = [];

    /** @var list<array{storage: PayloadStorageInterface, payload: object}> */
    private array $queued = [];

    private bool $clear = false;

    public bool $empty {
        get => !$this->clear && $this->queued === [];
    }

    public bool $cleared {
        get => $this->clear;
    }

    public function register(PayloadStorageInterface $storage): void
    {
        $this->storages[spl_object_id($storage)] = $storage;
    }

    public function queue(PayloadStorageInterface $storage, object $payload): void
    {
        $this->register($storage);

        if (!$this->clear) {
            $this->queued[] = ['storage' => $storage, 'payload' => $payload];
        }
    }

    /** Cancels pending credential writes after a terminal authentication denial. */
    public function discardQueued(): void
    {
        $this->queued = [];
    }

    public function clear(PayloadStorageInterface $storage): void
    {
        $this->register($storage);
        $this->clear = true;
        $this->queued = [];
    }

    public function apply(
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface {
        if ($this->clear) {
            foreach ($this->storages as $storage) {
                $response = $storage->remove($request, $response);
            }

            return CredentialResponseHeaders::apply($response);
        }

        if ($this->queued === []) {
            return $response;
        }

        foreach ($this->queued as $entry) {
            $response = $entry['storage']->store(
                $request,
                $response,
                $entry['payload'],
            );
        }

        return CredentialResponseHeaders::apply($response);
    }
}
