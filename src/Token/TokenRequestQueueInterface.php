<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/**
 * Durable queue used by the uniform token-request HTTP path.
 *
 * Every message carries a required purpose. Adapters serving multiple one-time
 * flows must route on that purpose without replacing it. Purpose-bound workers
 * reject a request routed to the wrong processor.
 *
 * Production adapters should enqueue without running provider lookup or
 * credential delivery inline when account-existence timing matters. Workers
 * must serialize requests sharing the same purpose and identity in enqueue
 * order because the built-in manager deliberately keeps one current token per
 * subject for each purpose-specific store.
 */
interface TokenRequestQueueInterface
{
    public function enqueue(TokenRequest $request): void;
}
