<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/**
 * Durable queue used by the uniform token-request HTTP path.
 *
 * Production adapters should enqueue without running provider lookup or
 * credential delivery inline when account-existence timing matters.
 */
interface TokenRequestQueueInterface
{
    public function enqueue(TokenRequest $request): void;
}
