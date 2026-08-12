<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenConfig
{
    public const string DATE_FORMAT = 'Y-m-d H:i:s';

    private const int MAX_TTL = 31536000;

    public string $dateFormat;

    public function __construct(
        public string $table,
        public string $purpose,
        public int $ttl = 300,
        public string $idColumn = 'id',
        public string $subjectIdColumn = 'user_id',
        public string $tokenColumn = 'token',
        public string $expiresAtColumn = 'expires_at',
        public string $usedAtColumn = 'used_at',
        public string $createdAtColumn = 'created_at',
    ) {
        $this->dateFormat = self::DATE_FORMAT;

        if (
            preg_match('/\A[a-z][a-z0-9._-]{0,63}\z/D', $this->purpose) !== 1
        ) {
            throw new \InvalidArgumentException(
                'One-time token purpose must be a bounded machine-readable identifier.',
            );
        }

        if ($this->ttl < 1 || $this->ttl > self::MAX_TTL) {
            throw new \InvalidArgumentException(sprintf(
                'Token TTL must be between 1 and %d seconds.',
                self::MAX_TTL,
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
