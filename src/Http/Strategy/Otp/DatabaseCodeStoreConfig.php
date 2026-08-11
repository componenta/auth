<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

final readonly class DatabaseCodeStoreConfig
{
    public function __construct(
        public string $table = 'otp_codes',
        public string $destinationColumn = 'destination',
        public string $subjectIdColumn = 'user_id',
        public string $challengeIdColumn = 'challenge_id',
        public string $verifierColumn = 'verifier',
        public string $expiresAtColumn = 'expires_at',
        public string $attemptsColumn = 'attempts',
    ) {
        foreach ([
            'table' => $this->table,
            'destinationColumn' => $this->destinationColumn,
            'subjectIdColumn' => $this->subjectIdColumn,
            'challengeIdColumn' => $this->challengeIdColumn,
            'verifierColumn' => $this->verifierColumn,
            'expiresAtColumn' => $this->expiresAtColumn,
            'attemptsColumn' => $this->attemptsColumn,
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
