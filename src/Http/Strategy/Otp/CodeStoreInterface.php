<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Stores one versioned OTP challenge per destination.
 *
 * Verification is a single atomic operation over one locked/versioned record:
 * attempt increment, expiry check, constant-time verifier comparison and
 * consume must not be split across independent calls. Implementations should
 * persist a keyed verifier (for example HMAC) rather than a canonical
 * low-entropy code when the backing store can be read independently.
 */
interface CodeStoreInterface
{
    public function store(StoredCode $code): void;

    public function verifyAndConsume(
        string $destination,
        string $presentedCode,
        int $now,
        int $maxAttempts,
    ): CodeVerificationResult;

    public function invalidate(string $destination): void;
}
