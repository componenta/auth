<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Stores and retrieves OTP codes.
 *
 * Keyed by destination (phone number, email address).
 * Only one active code per destination at a time -
 * storing a new code replaces any existing one.
 *
 * Implementation examples: Redis with TTL, database table
 * with cleanup, in-memory for testing.
 */
interface CodeStoreInterface
{
    /**
     * Stores a code. Replaces any existing code for this destination.
     */
    public function store(StoredCode $code): void;

    /**
     * Finds an active code by destination.
     */
    public function find(string $destination): ?StoredCode;

    /**
     * Removes the code for the given destination.
     */
    public function invalidate(string $destination): void;

    /**
     * Atomically finds and removes the code for the given destination.
     *
     * Prevents replay attacks where two concurrent requests with the
     * correct code both pass verification. The second request will
     * receive null because the code was already consumed.
     *
     * @return StoredCode|null The code if it existed, null if already consumed
     */
    public function consume(string $destination): ?StoredCode;

    /**
     * Increments the attempt counter for the given destination.
     *
     * @return int The new attempt count after incrementing
     */
    public function incrementAttempts(string $destination): int;
}
