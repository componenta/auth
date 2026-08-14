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

    /** @var list<\Closure(): void> */
    private array $discardCallbacks = [];

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

    /**
     * Registers compensation for a durable transition whose response-side
     * replacement credential has not been published yet.
     */
    public function onDiscard(\Closure $callback): void
    {
        if ($this->clear) {
            $callback();
            return;
        }

        $this->discardCallbacks[] = $callback;
    }

    /**
     * Cancels pending credential writes and compensates unpublished durable
     * transitions. Every callback is attempted before the first failure is
     * rethrown so one broken cleanup does not prevent the remaining cleanups.
     */
    public function discardQueued(): void
    {
        $this->queued = [];
        $callbacks = array_reverse($this->discardCallbacks);
        $this->discardCallbacks = [];
        $failure = null;

        foreach ($callbacks as $callback) {
            try {
                $callback();
            } catch (\Throwable $exception) {
                $failure ??= $exception;
            }
        }

        if ($failure !== null) {
            throw $failure;
        }
    }

    public function clear(PayloadStorageInterface $storage): void
    {
        $this->register($storage);
        $this->clear = true;
        $this->discardQueued();
    }

    public function apply(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
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

        try {
            foreach ($this->queued as $entry) {
                $response = $entry['storage']->store(
                    $request,
                    $response,
                    $entry['payload'],
                );
            }
        } catch (\Throwable $exception) {
            // No response carrying the queued bearers will be returned.
            $this->discardQueued();
            throw $exception;
        }

        $this->queued = [];
        $this->discardCallbacks = [];

        return CredentialResponseHeaders::apply($response);
    }
}
