<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\DeleteQuery;
use Cycle\Database\Query\SelectQuery;

/** SQL remember-me grants with replay detection, bearer rotation and session lineage revocation. */
final readonly class DatabaseRememberMeTokenManager implements RememberMeTokenManagerInterface
{
    private const int REVOKE_CHUNK_SIZE = 500;
    private const int MAX_CLEANUP_LIMIT = 10000;
    private const int MAX_ID_LENGTH = 512;

    private DateTimeFactoryInterface $dateTimeFactory;

    public function __construct(
        #[\SensitiveParameter]
        private DatabaseInterface $database,
        DateTimeFactoryInterface $dateTimeFactory,
        private DatabaseRememberMeTokenManagerConfig $config = new DatabaseRememberMeTokenManagerConfig(),
    ) {
        $this->dateTimeFactory = $dateTimeFactory->withTimezone('UTC');
    }

    #[\Override]
    public function create(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $sessionId,
    ): string {
        self::assertId($sessionId, 'Session ID');
        $selector = self::selector();
        $validator = self::validator();
        $now = $this->dateTimeFactory->now();

        $this->database->insert($this->config->table)->values([
            $this->config->subjectIdColumn => $subjectId->toString(),
            $this->config->sessionIdColumn => $sessionId,
            $this->config->previousSessionIdColumn => null,
            $this->config->tokenColumn => $selector,
            $this->config->verifierColumn => self::hash($validator),
            $this->config->expiresAtColumn => $now
                ->modify("+{$this->config->ttl} seconds")
                ->format($this->config->dateFormat),
            $this->config->createdAtColumn => $now->format($this->config->dateFormat),
        ])->run();

        return self::credential($selector, $validator);
    }

    #[\Override]
    public function rotate(
        #[\SensitiveParameter]
        string $plainToken,
    ): RememberMeRotation|RememberMeCompromise|null {
        $credential = self::parseCredential($plainToken);

        if ($credential === null) {
            return null;
        }

        [$selector, $validator] = $credential;
        $row = $this->findBySelector($selector);

        if ($row === null) {
            return null;
        }

        $now = $this->dateTimeFactory->now();
        $formattedNow = $now->format($this->config->dateFormat);

        if (self::stringValue($row, $this->config->expiresAtColumn) <= $formattedNow) {
            $this->deleteExpiredGrant($row, $selector, $formattedNow);

            return null;
        }

        $presentedVerifier = self::hash($validator);
        $storedVerifier = self::stringValue($row, $this->config->verifierColumn);

        if (!hash_equals($storedVerifier, $presentedVerifier)) {
            return $this->compromise($row, $selector);
        }

        $expiresAt = $now->modify("+{$this->config->ttl} seconds");
        $successorValidator = self::validator();
        $affected = $this->database
            ->update($this->config->table)
            ->where($this->config->idColumn, self::intValue($row, $this->config->idColumn))
            ->where($this->config->tokenColumn, $selector)
            ->where($this->config->verifierColumn, $presentedVerifier)
            ->where($this->config->expiresAtColumn, '>', $formattedNow)
            ->values([
                $this->config->verifierColumn => self::hash($successorValidator),
                $this->config->expiresAtColumn => $expiresAt->format($this->config->dateFormat),
                $this->config->createdAtColumn => $formattedNow,
            ])
            ->run();

        if ($affected !== 1) {
            $current = $this->findBySelector($selector);

            if ($current === null) {
                return null;
            }

            if (self::stringValue($current, $this->config->expiresAtColumn) <= $formattedNow) {
                $this->deleteExpiredGrant($current, $selector, $formattedNow);

                return null;
            }

            if (
                hash_equals(
                    self::stringValue($current, $this->config->verifierColumn),
                    $presentedVerifier,
                )
            ) {
                return null;
            }

            return $this->compromise($current, $selector);
        }

        return new RememberMeRotation(
            subjectId: self::uuidValue($row, $this->config->subjectIdColumn),
            previousSessionId: self::stringValue($row, $this->config->sessionIdColumn),
            successorToken: self::credential($selector, $successorValidator),
            expiresAt: $expiresAt,
        );
    }

    #[\Override]
    public function bindRotation(
        #[\SensitiveParameter]
        RememberMeRotation $rotation,
        #[\SensitiveParameter]
        string $newSessionId,
    ): bool {
        self::assertId($newSessionId, 'New session ID');
        $oldSessionId = $rotation->previousSessionId;
        self::assertId($oldSessionId, 'Previous session ID');
        $credential = self::parseCredential($rotation->successorToken);

        if ($credential === null) {
            return false;
        }

        [$selector, $validator] = $credential;
        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);
        $verifier = self::hash($validator);

        $affected = $this->database
            ->update($this->config->table)
            ->where($this->config->tokenColumn, $selector)
            ->where($this->config->verifierColumn, $verifier)
            ->where($this->config->subjectIdColumn, $rotation->subjectId->toString())
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->where($this->config->expiresAtColumn, '>', $now)
            ->values([
                $this->config->previousSessionIdColumn => $oldSessionId,
                $this->config->sessionIdColumn => $newSessionId,
            ])
            ->run();

        if ($affected === 1) {
            return true;
        }

        $row = $this->findBySelector($selector);

        return $row !== null
            && hash_equals(
                self::stringValue($row, $this->config->verifierColumn),
                $verifier,
            )
            && self::stringValue($row, $this->config->subjectIdColumn)
                === $rotation->subjectId->toString()
            && self::stringValue($row, $this->config->sessionIdColumn)
                === $newSessionId
            && self::nullableStringValue($row, $this->config->previousSessionIdColumn)
                === $oldSessionId
            && self::stringValue($row, $this->config->expiresAtColumn) > $now;
    }

    #[\Override]
    public function revoke(
        #[\SensitiveParameter]
        string $plainToken,
    ): void {
        $credential = self::parseCredential($plainToken);

        if ($credential === null) {
            return;
        }

        $this->database
            ->delete($this->config->table)
            ->where($this->config->tokenColumn, $credential[0])
            ->run();
    }

    #[\Override]
    public function revokeForSession(
        #[\SensitiveParameter]
        string $sessionId,
    ): void {
        $this->revokeForSessions([$sessionId]);
    }

    #[\Override]
    public function revokeForSessions(
        #[\SensitiveParameter]
        iterable $sessionIds,
    ): void {
        /** @var array<string, string> $ids */
        $ids = [];

        foreach ($sessionIds as $sessionId) {
            if (!is_string($sessionId)) {
                throw new \InvalidArgumentException(
                    'Every session ID must be a string.',
                );
            }

            self::assertId($sessionId, 'Session ID');
            $ids[self::idKey($sessionId)] = $sessionId;
        }

        foreach (array_chunk(array_values($ids), self::REVOKE_CHUNK_SIZE) as $chunk) {
            $this->database
                ->delete($this->config->table)
                ->where(function (mixed $query) use ($chunk): void {
                    if (!$query instanceof DeleteQuery) {
                        throw new \LogicException('Cycle must provide a DeleteQuery to the predicate.');
                    }

                    $query
                        ->where($this->config->sessionIdColumn, 'IN', $chunk)
                        ->orWhere($this->config->previousSessionIdColumn, 'IN', $chunk);
                })
                ->run();
        }
    }

    #[\Override]
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        ?string $exceptSessionId = null,
    ): void {
        $delete = $this->database
            ->delete($this->config->table)
            ->where($this->config->subjectIdColumn, $subjectId->toString());

        if ($exceptSessionId !== null) {
            self::assertId($exceptSessionId, 'Session ID');
            $delete->where($this->config->sessionIdColumn, '!=', $exceptSessionId);
        }

        $delete->run();
    }

    #[\Override]
    public function updateSessionId(
        #[\SensitiveParameter]
        string $oldSessionId,
        #[\SensitiveParameter]
        string $newSessionId,
    ): void {
        self::assertId($oldSessionId, 'Old session ID');
        self::assertId($newSessionId, 'New session ID');
        $this->database
            ->update($this->config->table)
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->values([
                $this->config->previousSessionIdColumn => $oldSessionId,
                $this->config->sessionIdColumn => $newSessionId,
            ])
            ->run();
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'Remember-me cleanup limit must be between 1 and %d.',
                self::MAX_CLEANUP_LIMIT,
            ));
        }

        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);
        $rows = $this->database
            ->select($this->config->idColumn)
            ->from($this->config->table)
            ->where($this->config->expiresAtColumn, '<=', $now)
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = [];

        foreach ($rows as $row) {
            if (is_array($row)) {
                $ids[] = self::intValue($row, $this->config->idColumn);
            }
        }

        $deleted = 0;

        foreach (array_chunk($ids, self::REVOKE_CHUNK_SIZE) as $chunk) {
            $deleted += $this->database
                ->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $chunk)
                ->where($this->config->expiresAtColumn, '<=', $now)
                ->run();
        }

        return $deleted;
    }

    /** @param array<array-key, mixed> $row */
    private function compromise(
        #[\SensitiveParameter]
        array $row,
        #[\SensitiveParameter]
        string $selector,
    ): RememberMeCompromise {
        $this->database
            ->delete($this->config->table)
            ->where($this->config->idColumn, self::intValue($row, $this->config->idColumn))
            ->where($this->config->tokenColumn, $selector)
            ->run();

        $sessionIds = [self::stringValue($row, $this->config->sessionIdColumn)];
        $previousSessionId = self::nullableStringValue(
            $row,
            $this->config->previousSessionIdColumn,
        );

        if ($previousSessionId !== null) {
            $sessionIds[] = $previousSessionId;
        }

        return new RememberMeCompromise(
            self::uuidValue($row, $this->config->subjectIdColumn),
            $sessionIds,
        );
    }

    /** @param array<array-key, mixed> $row */
    private function deleteExpiredGrant(
        #[\SensitiveParameter]
        array $row,
        #[\SensitiveParameter]
        string $selector,
        string $now,
    ): void {
        $this->database
            ->delete($this->config->table)
            ->where($this->config->idColumn, self::intValue($row, $this->config->idColumn))
            ->where($this->config->tokenColumn, $selector)
            ->where($this->config->expiresAtColumn, '<=', $now)
            ->run();
    }

    /** @return array<array-key, mixed>|null */
    private function findBySelector(
        #[\SensitiveParameter]
        string $selector,
    ): ?array {
        $query = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        $row = $query
            ->from($this->config->table)
            ->where($this->config->tokenColumn, $selector)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    private static function selector(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function validator(): string
    {
        return bin2hex(random_bytes(32));
    }

    private static function credential(
        #[\SensitiveParameter]
        string $selector,
        #[\SensitiveParameter]
        string $validator,
    ): string {
        return $selector . '.' . $validator;
    }

    /** @return array{string, string}|null */
    private static function parseCredential(
        #[\SensitiveParameter]
        string $credential,
    ): ?array {
        if (
            preg_match(
                '/\A([a-f0-9]{32})\.([a-f0-9]{64})\z/D',
                $credential,
                $matches,
            ) !== 1
        ) {
            return null;
        }

        return [$matches[1], $matches[2]];
    }

    private static function hash(
        #[\SensitiveParameter]
        string $validator,
    ): string {
        return hash('sha256', $validator);
    }

    private static function idKey(
        #[\SensitiveParameter]
        string $value,
    ): string {
        return 's:' . $value;
    }

    private static function assertId(
        #[\SensitiveParameter]
        string $value,
        string $label,
    ): void {
        if (
            $value === ''
            || strlen($value) > self::MAX_ID_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): string {
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
    private static function nullableStringValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): ?string {
        return !array_key_exists($key, $row) || $row[$key] === null
            ? null
            : self::stringValue($row, $key);
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): int {
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
    private static function uuidValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): UuidInterface {
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