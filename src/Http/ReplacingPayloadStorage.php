<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Replaces existing browser authentication state before storing a new one. */
final readonly class ReplacingPayloadStorage implements PayloadStorageInterface
{
    public function __construct(
        private PayloadStorageInterface $storage,
    ) {}

    #[\Override]
    public function store(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        object $payload,
    ): ResponseInterface {
        $transportState = $request->getAttribute(CredentialTransportState::class);
        if ($transportState instanceof CredentialTransportState) {
            $transportState->discardQueued();
        }

        $response = $this->storage->remove($request, $response);

        return $this->storage->store($request, $response, $payload);
    }

    #[\Override]
    public function remove(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return $this->storage->remove($request, $response);
    }
}
