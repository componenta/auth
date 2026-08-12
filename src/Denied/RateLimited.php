<?php

declare(strict_types=1);

namespace Componenta\Auth\Denied;

use Componenta\Auth\DeniedReasonInterface;

/** Too many authentication attempts. */
final class RateLimited implements DeniedReasonInterface, \JsonSerializable
{
    public string $code {
        get => 'rate_limited';
    }

    public function __construct(
        public int $retryAfter,
    ) {
        if ($this->retryAfter < 0) {
            throw new \InvalidArgumentException(
                'Rate-limit retryAfter must be greater than or equal to zero.',
            );
        }
    }

    /** @var array<string, mixed> */
    public array $attributes {
        get { return ['retry_after' => $this->retryAfter]; }
    }

    /** @return array{code: string} */
    public function __debugInfo(): array
    {
        return ['code' => $this->code];
    }

    /** @return array{code: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
