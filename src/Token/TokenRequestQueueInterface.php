<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/** Durable queue used by the uniform token-request HTTP path. */
interface TokenRequestQueueInterface
{
    public function enqueue(TokenRequest $request): void;
}
