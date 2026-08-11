<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\SelectQuery;

/**
 * SQL refresh-grant store with family-level serialization.
 *
 * The family row is the serialization point. Every rotation mutates a random
 * lock nonce before inspecting token state, so concurrent rotations for the
 * same family are ordered without dialect-specific SELECT ... FOR UPDATE.
 * Bearer token IDs are persisted only as SHA-256 hashes.
 */
final readonly class DatabaseRefreshTokenStore implements RefreshTokenStoreInterface
{
    private const int LOCK_NONCE_BYTES = 16;

    public function __construct(
        private DatabaseInterface $database,
        private DatabaseRefreshTokenStoreConfig $config = new DatabaseRefreshTokenStoreConfig(),
    ) {}

    #[\Override]
    public function storeInitial(RefreshToken $token): void
    {
        if ($token->revoked) {
            throw new \InvalidArgumentException(
                'An initial refresh token must be active.',
            );
        }

        $this->database->transaction(function (DatabaseInterface $database) use ($token): void {
            $database
                ->insert($this->config->familyTable)
                ->values([
                    $this->config->familyIdColumn => $token->familyId,
                    $this->config->subjectIdColumn => $token->subjectId->toString(),
                    $this->config->compromisedAtColumn => null,
                    $this->config->lockNonceColumn => self::lockNonce(),
                ])
                ->run();

            $database
                ->insert($this->config->tokenTable)
                ->values([
                    $this->config->tokenHashColumn => self::hashToken($token->id),
                    $this->config->familyIdColumn => $token->familyId,
                    $this->config->subjectIdColumn => $token->subjectId->toString(),
                    $this->config->expiresAtColumn => $token->expiresAt,
                    $this->config->consumedAtColumn => null,
                    $this->config->revokedAtColumn => null,
                ])
                ->run();
        });
    }

    #[\Override]
    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        if (!self::validIdentifier($presentedTokenId)) {
            return RefreshTokenRotationResult::invalid();
        }

        if (!self::validIdentifier($successorTokenId)) {
            throw new \InvalidArgumentException(
                'Successor refresh token ID is invalid.',
            );
        }

        if ($now < 1 || $successorExpiresAt <= $now) {
            throw new \InvalidArgumentException(
                'Refresh rotation timestamps are invalid.',
            );
        }

        $presentedHash = self::hashToken($presentedTokenId);
        $candidate = $this->findToken($this->database, $presentedHash);

        if ($candidate === null) {
            return RefreshTokenRotationResult::invalid();
        }

        $familyId = self::stringValue(
            $candidate,
            $this->config->familyIdColumn,
        );

        return $this->database->transaction(
            function (DatabaseInterface $database) use (
                $presentedHash,
                $successorTokenId,
                $successorExpiresAt,
                $now,
                $familyId,
            ): RefreshTokenRotationResult {
                if (!$this->claimActiveFamily($database, $familyId)) {
                    return RefreshTokenRotationResult::reused();
                }

                $family = $this->findFamily($database, $familyId);

                if ($family === null) {
                    throw new \UnexpectedValueException(
                        'Refresh token references a missing family.',
                    );
                }

                $token = $this->findToken($database, $presentedHash);

                if ($token === null) {
                    throw new \UnexpectedValueException(
                        'Refresh token disappeared while its family was locked.',
                    );
                }

                if (
                    self::stringValue($token, $this->config->familyIdColumn)
                    !== $familyId
                ) {
                    throw new \UnexpectedValueException(
                        'Refresh token family changed during rotation.',
                    );
                }

                if (self::nullableIntValue(
                    $token,
                    $this->config->consumedAtColumn,
                ) !== null) {
                    $this->compromiseFamily($database, $familyId, $now);

                    return RefreshTokenRotationResult::reused();
                }

                if (self::nullableIntValue(
                    $token,
                    $this->config->revokedAtColumn,
                ) !== null) {
                    return RefreshTokenRotationResult::invalid();
                }

                if (
                    self::intValue($token, $this->config->expiresAtColumn)
                    <= $now
                ) {
                    return RefreshTokenRotationResult::expired();
                }

                $affected = $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->tokenHashColumn, $presentedHash)
                    ->where($this->config->consumedAtColumn, null)
                    ->where($this->config->revokedAtColumn, null)
                    ->where($this->config->expiresAtColumn, '>', $now)
                    ->values([
                        $this->config->consumedAtColumn => $now,
                        $this->config->revokedAtColumn => $now,
                    ])
                    ->run();

                if ($affected !== 1) {
                    throw new \UnexpectedValueException(
                        'Refresh token could not be claimed after its family was locked.',
                    );
                }

                $subjectId = self::uuidValue(
                    $family,
                    $this->config->subjectIdColumn,
                );
                $tokenSubjectId = self::uuidValue(
                    $token,
                    $this->config->subjectIdColumn,
                );

                if (!$subjectId->equals($tokenSubjectId)) {
                    throw new \UnexpectedValueException(
                        'Refresh token subject does not match its family.',
                    );
                }

                $database
                    ->insert($this->config->tokenTable)
                    ->values([
                        $this->config->tokenHashColumn => self::hashToken(
                            $successorTokenId,
                        ),
                        $this->config->familyIdColumn => $familyId,
                        $this->config->subjectIdColumn => $subjectId->toString(),
                        $this->config->expiresAtColumn => $successorExpiresAt,
                        $this->config->consumedAtColumn => null,
                        $this->config->revokedAtColumn => null,
                    ])
                    ->run();

                return RefreshTokenRotationResult::rotated(new RefreshToken(
                    id: $successorTokenId,
                    subjectId: $subjectId,
                    familyId: $familyId,
                    expiresAt: $successorExpiresAt,
                ));
            },
        );
    }

    #[\Override]
    public function revoke(string $tokenId, int $revokedAt): void
    {
        if (!self::validIdentifier($tokenId)) {
            return;
        }

        if ($revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $tokenHash = self::hashToken($tokenId);
        $candidate = $this->findToken($this->database, $tokenHash);

        if ($candidate === null) {
            return;
        }

        $familyId = self::stringValue(
            $candidate,
            $this->config->familyIdColumn,
        );

        $this->database->transaction(
            function (DatabaseInterface $database) use (
                $tokenHash,
                $familyId,
                $revokedAt,
            ): void {
                $this->claimFamily($database, $familyId);

                $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->tokenHashColumn, $tokenHash)
                    ->where($this->config->revokedAtColumn, null)
                    ->values([
                        $this->config->revokedAtColumn => $revokedAt,
                    ])
                    ->run();
            },
        );
    }

    #[\Override]
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void {
        if ($revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $subject = $subjectId->toString();

        $this->database->transaction(
            function (DatabaseInterface $database) use (
                $subject,
                $revokedAt,
            ): void {
                $database
                    ->update($this->config->familyTable)
                    ->where($this->config->subjectIdColumn, $subject)
                    ->where($this->config->compromisedAtColumn, null)
                    ->values([
                        $this->config->compromisedAtColumn => $revokedAt,
                        $this->config->lockNonceColumn => self::lockNonce(),
                    ])
                    ->run();

                $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->subjectIdColumn, $subject)
                    ->where($this->config->revokedAtColumn, null)
                    ->values([
                        $this->config->revokedAtColumn => $revokedAt,
                    ])
                    ->run();
            },
        );
    }

    private function claimActiveFamily(
        DatabaseInterface $database,
        string $familyId,
    ): bool {
        $affected = $database
            ->update($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->compromisedAtColumn, null)
            ->values([
                $this->config->lockNonceColumn => self::lockNonce(),
            ])
            ->run();

        if ($affected === 1) {
            return true;
        }

        $family = $this->findFamily($database, $familyId);

        if ($family === null) {
            throw new \UnexpectedValueException(
                'Refresh token references a missing family.',
            );
        }

        if (self::nullableIntValue(
            $family,
            $this->config->compromisedAtColumn,
        ) !== null) {
            return false;
        }

        throw new \UnexpectedValueException(
            'Refresh token family could not be serialized.',
        );
    }

    private function claimFamily(
        DatabaseInterface $database,
        string $familyId,
    ): void {
        $affected = $database
            ->update($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->values([
                $this->config->lockNonceColumn => self::lockNonce(),
            ])
            ->run();

        if ($affected !== 1) {
            throw new \UnexpectedValueException(
                'Refresh token references a missing family.',
            );
        }
    }

    private function compromiseFamily(
        DatabaseInterface $database,
        string $familyId,
        int $now,
    ): void {
        $database
            ->update($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->compromisedAtColumn, null)
            ->values([
                $this->config->compromisedAtColumn => $now,
                $this->config->lockNonceColumn => self::lockNonce(),
            ])
            ->run();

        $database
            ->update($this->config->tokenTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->revokedAtColumn, null)
            ->values([
                $this->config->revokedAtColumn => $now,
            ])
            ->run();
    }

    /** @return array<array-key, mixed>|null */
    private function findToken(
        DatabaseInterface $database,
        string $tokenHash,
    ): ?array {
        $row = $this->writeSelect($database)
            ->from($this->config->tokenTable)
            ->where($this->config->tokenHashColumn, $tokenHash)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    /** @return array<array-key, mixed>|null */
    private function findFamily(
        DatabaseInterface $database,
        string $familyId,
    ): ?array {
        $row = $this->writeSelect($database)
            ->from($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    /**
     * Security-state reads must use the same primary/write connection as the
     * transaction. Cycle Database::select() otherwise prefers a read replica.
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

    private static function lockNonce(): string
    {
        return bin2hex(random_bytes(self::LOCK_NONCE_BYTES));
    }

    private static function hashToken(string $tokenId): string
    {
        return hash('sha256', $tokenId);
    }

    private static function validIdentifier(string $value): bool
    {
        return preg_match('/\A[a-f0-9]{64,128}\z/D', $value) === 1
            && strlen($value) % 2 === 0;
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
    private static function nullableIntValue(array $row, string $key): ?int
    {
        if (!array_key_exists($key, $row) || $row[$key] === null) {
            return null;
        }

        return self::intValue($row, $key);
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
