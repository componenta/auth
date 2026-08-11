<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

final readonly class OtpConfig
{
    public const int MIN_LENGTH = 6;
    public const int MAX_LENGTH = 18;
    private const int MAX_TTL = 600;
    private const int MAX_ATTEMPTS = 100;

    public function __construct(
        public int $length = 6,
        public int $ttl = 300,
        public int $maxAttempts = 5,
    ) {
        if ($this->length < self::MIN_LENGTH || $this->length > self::MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf(
                'Code length must be between %d and %d digits.',
                self::MIN_LENGTH,
                self::MAX_LENGTH,
            ));
        }

        if ($this->ttl < 1 || $this->ttl > self::MAX_TTL) {
            throw new \InvalidArgumentException(sprintf(
                'OTP TTL must be between 1 and %d seconds.',
                self::MAX_TTL,
            ));
        }

        if ($this->maxAttempts < 1 || $this->maxAttempts > self::MAX_ATTEMPTS) {
            throw new \InvalidArgumentException(sprintf(
                'Max attempts must be between 1 and %d.',
                self::MAX_ATTEMPTS,
            ));
        }
    }
}
