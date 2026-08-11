<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\DeleteQuery;
use Cycle\Database\Query\SelectQuery;

final readonly class DatabaseRememberMeTokenManager implements RememberMeTokenManagerInterface
{
    private const int REVOKE_CHUNK_SIZE = 500;
    private const int MAX_CLEANUP_LIMIT = 10000;
    private const int MAX_ID_LENGTH = 512;

    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private DatabaseRememberMeTokenManagerConfig $config = new DatabaseRememberMeTokenManagerConfig(),
    ) {}

    #[\Override]
    public function create(
        UuidInterface $subjectId,
        ?string $sessionId = null,
    ): string {
        if ($sessionId !== null) {
            self::assertId($sessionId, 'Session ID');
        }

        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();
        $this->database->insert($this->config->table)->values([
            $this->config->subjectIdColumn => $subjectId->toString(),
            $this->config->sessionIdColumn => $sessionId,
            $this->config->tokenColumn => self::hash($plainToken),
            $this->config->expiresAtColumn => $now
                ->modify("+{$this->config->ttl} seconds")
                ->format($this->config->dateFormat),
            $this->config->createdAtColumn => $now->format($this->config->dateFormat),
        ])->run();

        return $plainToken;
    }

    #[\Override]
    public function consume(string $plainToken): ?RememberMeToken
    {
        if (!self::validToken($plainToken)) {
            return null;
        }

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
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->run()
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        $token = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        if ($token->expiresAt <= $now) {
            $this->database
                ->delete($this->config->table)
                ->where($this->config->idColumn, $token->id)
                ->run();

            return null;
        }

        $affectedRows = $this->database
            ->delete($this->config->table)
            ->where($this->config->idColumn, $token->id)
            ->where(
                $this->config->expiresAtColumn,
                '>',
                $now->format($this->config->dateFormat),
            )
            ->run();

        return $affectedRows === 0 ? null : $token;
    }

    #[\Override]
    public function revoke(string $plainToken): void
    {
        if (!self::validToken($plainToken)) {
            return;
        }

        $this->database
            ->delete($this->config->table)
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->run();
    }

    #[\Override]
    public function revokeForSession(string $sessionId): void
    {
        $this->revokeForSessions([$sessionId]);
    }

    #[\Override]
    public function revokeForSessions(iterable $sessionIds): void
    {
        /** @var array<string, true> $ids */
        $ids = [];

        foreach ($sessionIds as $sessionId) {
            if (!is_string($sessionId)) {
                throw new \InvalidArgumentException(
                    'Every session ID must be a string.',
                );
            }

            self::assertId($sessionId, 'Session ID');
            $ids[$sessionId] = true;
        }

        foreach (array_chunk(array_keys($ids), self::REVOKE_CHUNK_SIZE) as $chunk) {
            $this->database
                ->delete($this->config->table)
                ->where($this->config->sessionIdColumn, 'IN', $chunk)
                ->run();
        }
    }

    #[\Override]
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        ?string $exceptSessionId = null,
    ): void {
        $delete = $this->database
            ->delete($this->config->table)
            ->where($this->config->subjectIdColumn, $subjectId->toString());

        if ($exceptSessionId !== null) {
            self::assertId($exceptSessionId, 'Session ID');
            $delete->where(function (mixed $query) use ($exceptSessionId): void {
                if (!$query instanceof DeleteQuery) {
                    throw new \LogicException('Cycle must provide a DeleteQuery to the predicate.');
                }

                $query
                    ->where($this->config->sessionIdColumn, '!=', $exceptSessionId)
                    ->orWhere($this->config->sessionIdColumn, null);
            });
        }

        $delete->run();
    }

    #[\Override]
    public function updateSessionId(
        string $oldSessionId,
        string $newSessionId,
    ): void {
        self::assertId($oldSessionId, 'Old session ID');
        self::assertId($newSessionId, 'New session ID');
        $this->database
            ->update($this->config->table)
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->values([$this->config->sessionIdColumn => $newSessionId])
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

    private static function validToken(string $token): bool
    {
        return preg_match('/\A[a-f0-9]{64}\z/D', $token) === 1;
    }

    private static function hash(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }

    private static function assertId(string $value, string $label): void
    {
        if (
            $value === ''
            || strlen($value) > self::MAX_ID_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }

    /** @param array<array-key, mixed> $row */
    private function hydrate(array $row): RememberMeToken
    {
        $sessionId = $row[$this->config->sessionIdColumn] ?? null;

        return new RememberMeToken(
            id: self::intValue($row, $this->config->idColumn),
            subjectId: Uuid::fromString(self::stringValue(
                $row,
                $this->config->subjectIdColumn,
            )),
            sessionId: $sessionId === null
                ? null
                : self::stringValue($row, $this->config->sessionIdColumn),
            expiresAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->expiresAtColumn,
            )),
            createdAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->createdAtColumn,
            )),
        );
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
}
