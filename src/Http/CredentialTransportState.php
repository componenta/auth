<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Request-scoped accumulator with terminal clear-over-store precedence. */
final class CredentialTransportState
{
    /** @var list<object> */
    private array $queuedPayloads = [];

    private bool $clear = false;

    public bool $empty {
        get => !$this->clear && $this->queuedPayloads === [];
    }

    public bool $cleared {
        get => $this->clear;
    }

    /** @var list<object> */
    public array $payloads {
        get => $this->queuedPayloads;
    }

    public function queue(object $payload): void
    {
        if (!$this->clear) {
            $this->queuedPayloads[] = $payload;
        }
    }

    public function clear(): void
    {
        $this->clear = true;
        $this->queuedPayloads = [];
    }

    public function apply(
        PayloadStorageInterface $storage,
        ServerRequestInterface $request,
        ResponseInterface $response,
    ): ResponseInterface {
        if ($this->clear) {
            return $storage->remove($request, $response);
        }

        foreach ($this->queuedPayloads as $payload) {
            $response = $storage->store($request, $response, $payload);
        }

        return $response;
    }
}
