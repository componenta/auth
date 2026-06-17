<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

final readonly class DatabaseRememberMeTokenManagerConfig
{
    public function __construct(
        public string $table = 'remember_me_tokens',
        public string $dateFormat = 'Y-m-d H:i:s',
        public int $ttl = 2592000,
        public string $idColumn = 'id',
        public string $userIdColumn = 'user_id',
        public string $tokenColumn = 'token',
        public string $sessionIdColumn = 'session_id',
        public string $expiresAtColumn = 'expires_at',
        public string $createdAtColumn = 'created_at',
    ) {}
}
