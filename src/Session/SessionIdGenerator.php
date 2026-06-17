<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Generates cryptographically secure session IDs.
 *
 * Uses random_bytes() for collision resistance.
 * Default 32 bytes = 256 bits of entropy.
 */
final readonly class SessionIdGenerator implements SessionIdGeneratorInterface
{
    public function __construct(
        private int $length = 32,
    ) {}

    public function generate(): string
    {
        return bin2hex(random_bytes($this->length));
    }
}
