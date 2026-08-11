<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class DatabaseSessionManagerConfig
{
    private const int MAX_TIMEOUT = 315360000;

    public function __construct(
        public string $table = 'sessions',
        public string $dateFormat = 'Y-m-d H:i:s',
        public bool $lazyLoad = true,
        public int $idleTimeout = 1800,
        public int $absoluteTimeout = 28800,
        public int $regenerationInterval = 300,
        public int $regenerationGracePeriod = 30,
        public int $touchInterval = 60,
        public string $idColumn = 'id',
        public string $subjectIdColumn = 'user_id',
        public string $ipColumn = 'ip',
        public string $userAgentColumn = 'user_agent',
        public string $expiresAtColumn = 'expires_at',
        public string $absoluteExpiresAtColumn = 'absolute_expires_at',
        public string $regenerateAtColumn = 'regenerate_at',
        public string $replacedByColumn = 'replaced_by',
        public string $createdAtColumn = 'created_at',
        public string $lastActiveAtColumn = 'last_active_at',
        public string $attributesColumn = 'attributes',
    ) {
        if ($this->dateFormat === '') {
            throw new \InvalidArgumentException('Date format must not be empty.');
        }

        foreach ([
            'idleTimeout' => $this->idleTimeout,
            'absoluteTimeout' => $this->absoluteTimeout,
            'regenerationInterval' => $this->regenerationInterval,
        ] as $name => $value) {
            if ($value < 1 || $value > self::MAX_TIMEOUT) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be between 1 and %d seconds.',
                    $name,
                    self::MAX_TIMEOUT,
                ));
            }
        }

        if ($this->absoluteTimeout < $this->idleTimeout) {
            throw new \InvalidArgumentException(
                'absoluteTimeout must be greater than or equal to idleTimeout.',
            );
        }

        if ($this->regenerationInterval >= $this->idleTimeout) {
            throw new \InvalidArgumentException(
                'regenerationInterval must be less than idleTimeout.',
            );
        }

        if (
            $this->regenerationGracePeriod < 0
            || $this->regenerationGracePeriod >= $this->idleTimeout
        ) {
            throw new \InvalidArgumentException(
                'regenerationGracePeriod must be non-negative and less than idleTimeout.',
            );
        }

        if ($this->touchInterval < 0 || $this->touchInterval >= $this->idleTimeout) {
            throw new \InvalidArgumentException(
                'touchInterval must be non-negative and less than idleTimeout.',
            );
        }

        foreach ([
            'table' => $this->table,
            'idColumn' => $this->idColumn,
            'subjectIdColumn' => $this->subjectIdColumn,
            'ipColumn' => $this->ipColumn,
            'userAgentColumn' => $this->userAgentColumn,
            'expiresAtColumn' => $this->expiresAtColumn,
            'absoluteExpiresAtColumn' => $this->absoluteExpiresAtColumn,
            'regenerateAtColumn' => $this->regenerateAtColumn,
            'replacedByColumn' => $this->replacedByColumn,
            'createdAtColumn' => $this->createdAtColumn,
            'lastActiveAtColumn' => $this->lastActiveAtColumn,
            'attributesColumn' => $this->attributesColumn,
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
