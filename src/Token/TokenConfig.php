<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/**
 * Configuration for database-backed one-time tokens.
 *
 * Used by TokenManager to define storage table and column mapping.
 * Each token flow (magic link, password reset, etc.) creates
 * its own TokenConfig instance with appropriate defaults.
 */
final readonly class TokenConfig
{
    /**
     * @param string $table Database table name
     * @param int $ttl Token lifetime in seconds
     * @param string $dateFormat Date format for database storage
     * @param string $idColumn Column name for primary key
     * @param string $userIdColumn Column name for user ID
     * @param string $tokenColumn Column name for token hash
     * @param string $expiresAtColumn Column name for expiration timestamp
     * @param string $usedAtColumn Column name for used-at timestamp
     * @param string $createdAtColumn Column name for creation timestamp
     */
    public function __construct(
        public string $table,
        public int $ttl = 300,
        public string $dateFormat = 'Y-m-d H:i:s',
        public string $idColumn = 'id',
        public string $userIdColumn = 'user_id',
        public string $tokenColumn = 'token',
        public string $expiresAtColumn = 'expires_at',
        public string $usedAtColumn = 'used_at',
        public string $createdAtColumn = 'created_at',
    ) {
        if ($this->ttl < 1) {
            throw new \InvalidArgumentException('TTL must be positive');
        }
    }
}
