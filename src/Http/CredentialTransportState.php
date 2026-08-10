<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Request-scoped accumulator for authentication transport mutations.
 *
 * Clearing credentials is terminal for the request: once clear() is called,
 * queued and future rotations are ignored. This prevents a credential created
 * during authentication from being written after a downstream logout.
 */
final class CredentialTransportState
{
    /** @var list<object> */
    private array $payloads = [];

    private bool $clear = false;

    public function queue(object $payload): void
    {
        if ($this->clear) {
            return;
        }

        $this->payloads[] = $payload;
    }

    public function clear(): void
    {
        $this->clear = true;
        $this->payloads = [];
    }

    public function isEmpty(): bool
    {
        return !$this->clear && $this->payloads === [];
    }

    public function shouldClear(): bool
    {
        return $this->clear;
    }

    /** @return list<object> */
    public function payloads(): array
    {
        return $this->payloads;
    }

    public function apply(
        PayloadStorageInterface $storage,
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface {
        if ($this->clear) {
            return $storage->remove($request, $response);
        }

        foreach ($this->payloads as $payload) {
            $response = $storage->store($request, $response, $payload);
        }

        return $response;
    }
}
