<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class DatabaseSessionManagerConfig
{
    public function __construct(
        public string $table = 'sessions',
        public string $dateFormat = 'Y-m-d H:i:s',
        public bool $lazyLoad = true,
        public int $idleTimeout = 1800,
        public int $absoluteTimeout = 28800,
        public int $regenerationInterval = 300,
        public int $regenerationGracePeriod = 30,
        public string $idColumn = 'id',
        public string $userIdColumn = 'user_id',
        public string $ipColumn = 'ip',
        public string $userAgentColumn = 'user_agent',
        public string $expiresAtColumn = 'expires_at',
        public string $absoluteExpiresAtColumn = 'absolute_expires_at',
        public string $regenerateAtColumn = 'regenerate_at',
        public string $replacedByColumn = 'replaced_by',
        public string $createdAtColumn = 'created_at',
        public string $lastActiveAtColumn = 'last_active_at',
        public string $attributesColumn = 'attributes',
    ) {}
}