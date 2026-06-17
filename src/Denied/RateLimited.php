<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * Too many authentication attempts.
 */
final class RateLimited implements DeniedReasonInterface
{
    public string $code {
        get => 'rate_limited';
    }

    public function __construct(
        public int $retryAfter,
    ) {}

    public array $attributes {
        get { return ['retry_after' => $this->retryAfter]; }
    }
}
