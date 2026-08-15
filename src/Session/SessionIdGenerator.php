<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/** Generates a bounded cryptographically secure hexadecimal session ID. */
final readonly class SessionIdGenerator implements SessionIdGeneratorInterface
{
    private const int MIN_BYTES = 16;
    private const int MAX_BYTES = 64;

    public function __construct(
        private int $length = 32,
    ) {
        if ($this->length < self::MIN_BYTES || $this->length > self::MAX_BYTES) {
            throw new \InvalidArgumentException(sprintf(
                'Session ID entropy must be between %d and %d bytes.',
                self::MIN_BYTES,
                self::MAX_BYTES,
            ));
        }
    }

    public function generate(): string
    {
        return bin2hex(random_bytes($this->length));
    }
}
