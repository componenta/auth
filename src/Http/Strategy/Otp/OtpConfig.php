<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Configuration for OTP authentication strategy.
 */
final readonly class OtpConfig
{
    /**
     * @param int $length Code length in digits (minimum 4)
     * @param int $ttl Code lifetime in seconds
     * @param int $maxAttempts Maximum verification attempts before invalidation
     */
    public function __construct(
        public int $length = 6,
        public int $ttl = 300,
        public int $maxAttempts = 5,
    ) {
        if ($this->length < 4) {
            throw new \InvalidArgumentException('Code length must be at least 4');
        }

        if ($this->ttl < 1) {
            throw new \InvalidArgumentException('TTL must be positive');
        }

        if ($this->maxAttempts < 1) {
            throw new \InvalidArgumentException('Max attempts must be positive');
        }
    }
}
