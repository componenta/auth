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

    public int $retryAfter {
        set {
            if ($value < 0) {
                throw new \InvalidArgumentException(
                    'Rate-limit retryAfter must be greater than or equal to zero.',
                );
            }

            $this->retryAfter = $value;
        }
    }

    public function __construct(int $retryAfter)
    {
        $this->retryAfter = $retryAfter;
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
