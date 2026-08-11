<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenConfig
{
    public const string DATE_FORMAT = 'Y-m-d H:i:s';

    private const int MAX_TTL = 31536000;

    public function __construct(
        public string $table,
        public int $ttl = 300,
        public string $dateFormat = self::DATE_FORMAT,
        public string $idColumn = 'id',
        public string $subjectIdColumn = 'user_id',
        public string $tokenColumn = 'token',
        public string $expiresAtColumn = 'expires_at',
        public string $usedAtColumn = 'used_at',
        public string $createdAtColumn = 'created_at',
    ) {
        if ($this->ttl < 1 || $this->ttl > self::MAX_TTL) {
            throw new \InvalidArgumentException(sprintf(
                'Token TTL must be between 1 and %d seconds.',
                self::MAX_TTL,
            ));
        }

        if ($this->dateFormat !== self::DATE_FORMAT) {
            throw new \InvalidArgumentException(sprintf(
                'One-time token database timestamps must use the sortable format %s.',
                self::DATE_FORMAT,
            ));
        }

        foreach ([
            'table' => $this->table,
            'idColumn' => $this->idColumn,
            'subjectIdColumn' => $this->subjectIdColumn,
            'tokenColumn' => $this->tokenColumn,
            'expiresAtColumn' => $this->expiresAtColumn,
            'usedAtColumn' => $this->usedAtColumn,
            'createdAtColumn' => $this->createdAtColumn,
        ] as $name => $identifier) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.]*\z/D', $identifier) !== 1) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be a valid trusted SQL identifier.',
                    $name,
                ));
            }
        }
    }
}
