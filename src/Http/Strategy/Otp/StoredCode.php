<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Represents a stored OTP code entry.
 */
final readonly class StoredCode
{
    public function __construct(
        public string $userId,
        public string $code,
        public string $destination,
        public int $expiresAt,
        public int $attempts = 0,
    ) {}
}
