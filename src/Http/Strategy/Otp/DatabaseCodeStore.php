<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use Cycle\Database\Query\SelectQuery;

/**
 * SQL OTP store using a keyed verifier and optimistic challenge-version CAS.
 *
 * Plain OTP codes are never persisted. The challenge ID changes on every
 * replacement and is included in every consume/attempt mutation, preventing a
 * stale verifier from mutating a newly issued challenge.
 */
final readonly class DatabaseCodeStore implements CodeStoreInterface
{
    private const int CHALLENGE_ID_BYTES = 16;
    private const int MAX_CAS_RETRIES = 16;
    private const int MIN_HMAC_KEY_BYTES = 32;
    private const int MAX_HMAC_KEY_BYTES = 4096;

    private string $dummyVerifier;

    public function __construct(
        private DatabaseInterface $database,
        #[\SensitiveParameter]
        private string $hmacKey,
        private DatabaseCodeStoreConfig $config = new DatabaseCodeStoreConfig(),
    ) {
        $length = strlen($this->hmacKey);

        if (
            $length < self::MIN_HMAC_KEY_BYTES
            || $length > self::MAX_HMAC_KEY_BYTES
        ) {
            throw new \InvalidArgumentException(sprintf(
                'OTP HMAC key must contain between %d and %d bytes.',
                self::MIN_HMAC_KEY_BYTES,
                self::MAX_HMAC_KEY_BYTES,
            ));
        }

        $this->dummyVerifier = hash_hmac(
            'sha256',
            'componenta-auth-otp-dummy',
            $this->hmacKey,
        );
    }

    #[\Override]
    public function store(StoredCode $code): void
    {
        $values = [
            $this->config->destinationColumn => $code->destination,
            $this->config->subjectIdColumn => $code->subjectId->toString(),
            $this->config->challengeIdColumn => self::challengeId(),
            $this->config->verifierColumn => $this->verifier(
                $code->destination,
                $code->code,
            ),
            $this->config->expiresAtColumn => $code->expiresAt,
            $this->config->attemptsColumn => 0,
        ];

        $this->database
            ->insert($this->config->table)
            ->values($values)
            ->onConflict(OnConflict::target(
                $this->config->destinationColumn,
            )->doUpdate([
                $this->config->subjectIdColumn,
                $this->config->challengeIdColumn,
                $this->config->verifierColumn,
                $this->config->expiresAtColumn,
                $this->config->attemptsColumn,
            ]))
            ->run();
    }

    #[\Override]
    public function verifyAndConsume(
        string $destination,
        string $presentedCode,
        int $now,
        int $maxAttempts,
    ): CodeVerificationResult {
        self::assertDestination($destination);
        self::assertCode($presentedCode);

        if ($now < 1) {
            throw new \InvalidArgumentException(
                'OTP verification time must be positive.',
            );
        }

        if ($maxAttempts < 1) {
            throw new \InvalidArgumentException(
                'OTP max attempts must be greater than zero.',
            );
        }

        $presentedVerifier = $this->verifier(
            $destination,
            $presentedCode,
        );

        for ($attempt = 0; $attempt < self::MAX_CAS_RETRIES; ++$attempt) {
            $row = $this->find($this->database, $destination);

            if ($row === null) {
                hash_equals($this->dummyVerifier, $presentedVerifier);

                return CodeVerificationResult::invalid();
            }

            $challengeId = self::stringValue(
                $row,
                $this->config->challengeIdColumn,
            );
            $attempts = self::intValue(
                $row,
                $this->config->attemptsColumn,
            );

            if ($attempts >= $maxAttempts) {
                return CodeVerificationResult::tooManyAttempts();
            }

            if (
                self::intValue($row, $this->config->expiresAtColumn)
                <= $now
            ) {
                $deleted = $this->database
                    ->delete($this->config->table)
                    ->where(
                        $this->config->destinationColumn,
                        $destination,
                    )
                    ->where(
                        $this->config->challengeIdColumn,
                        $challengeId,
                    )
                    ->run();

                if ($deleted === 1) {
                    return CodeVerificationResult::expired();
                }

                continue;
            }

            $storedVerifier = self::stringValue(
                $row,
                $this->config->verifierColumn,
            );

            if (hash_equals($storedVerifier, $presentedVerifier)) {
                $subjectId = self::uuidValue(
                    $row,
                    $this->config->subjectIdColumn,
                );
                $deleted = $this->database
                    ->delete($this->config->table)
                    ->where(
                        $this->config->destinationColumn,
                        $destination,
                    )
                    ->where(
                        $this->config->challengeIdColumn,
                        $challengeId,
                    )
                    ->where(
                        $this->config->verifierColumn,
                        $storedVerifier,
                    )
                    ->where(
                        $this->config->expiresAtColumn,
                        '>',
                        $now,
                    )
                    ->run();

                if ($deleted === 1) {
                    return CodeVerificationResult::verified($subjectId);
                }

                continue;
            }

            $nextAttempts = $attempts + 1;
            $affected = $this->database
                ->update($this->config->table)
                ->where(
                    $this->config->destinationColumn,
                    $destination,
                )
                ->where(
                    $this->config->challengeIdColumn,
                    $challengeId,
                )
                ->where(
                    $this->config->attemptsColumn,
                    $attempts,
                )
                ->where(
                    $this->config->expiresAtColumn,
                    '>',
                    $now,
                )
                ->values([
                    $this->config->attemptsColumn => $nextAttempts,
                ])
                ->run();

            if ($affected === 1) {
                return $nextAttempts >= $maxAttempts
                    ? CodeVerificationResult::tooManyAttempts()
                    : CodeVerificationResult::invalid();
            }
        }

        return CodeVerificationResult::tooManyAttempts();
    }

    #[\Override]
    public function invalidate(string $destination): void
    {
        self::assertDestination($destination);

        $this->database
            ->delete($this->config->table)
            ->where($this->config->destinationColumn, $destination)
            ->run();
    }

    /** @return array<array-key, mixed>|null */
    private function find(
        DatabaseInterface $database,
        string $destination,
    ): ?array {
        $row = $this->writeSelect($database)
            ->from($this->config->table)
            ->where($this->config->destinationColumn, $destination)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    /**
     * OTP state must never be read from a lagging replica because the CAS
     * mutation is executed on the primary/write connection.
     */
    private function writeSelect(DatabaseInterface $database): SelectQuery
    {
        $query = $database->select()->withDriver(
            $database->getDriver(DatabaseInterface::WRITE),
            $database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        return $query;
    }

    private function verifier(
        string $destination,
        #[\SensitiveParameter]
        string $code,
    ): string {
        return hash_hmac(
            'sha256',
            $destination . "\0" . $code,
            $this->hmacKey,
        );
    }

    private static function challengeId(): string
    {
        return bin2hex(random_bytes(self::CHALLENGE_ID_BYTES));
    }

    private static function assertDestination(string $destination): void
    {
        if (
            $destination === ''
            || strlen($destination) > 320
            || trim($destination) !== $destination
            || preg_match('/[\x00-\x1F\x7F]/', $destination) === 1
        ) {
            throw new \InvalidArgumentException(
                'OTP destination is invalid.',
            );
        }
    }

    private static function assertCode(
        #[\SensitiveParameter]
        string $code,
    ): void {
        if (preg_match(sprintf(
            '/\A[0-9]{%d,%d}\z/D',
            OtpConfig::MIN_LENGTH,
            OtpConfig::MAX_LENGTH,
        ), $code) !== 1) {
            throw new \InvalidArgumentException(
                'Presented OTP code is invalid.',
            );
        }
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(array $row, string $key): int
    {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain an integer.',
                $key,
            ));
        }

        return (int) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function uuidValue(array $row, string $key): UuidInterface
    {
        try {
            return Uuid::fromString(self::stringValue($row, $key));
        } catch (\InvalidArgumentException $exception) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" must contain a valid UUID.', $key),
                previous: $exception,
            );
        }
    }
}
