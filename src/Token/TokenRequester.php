<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/** Enqueues identical opaque work for known and unknown identities. */
final readonly class TokenRequester
{
    public function __construct(private TokenRequestQueueInterface $queue) {}

    /** @param array<string, string> $context */
    public function request(string $identity, ?string $destination = null, array $context = []): void
    {
        $this->queue->enqueue(new TokenRequest($identity, $destination, $context));
    }
}
