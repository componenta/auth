<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

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
    public function create(int|string $userId, ?string $sessionId = null): string
    {
        self::assertSubjectId($userId);

        if ($sessionId !== null) {
            self::assertId($sessionId, 'Session ID');
        }

        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();
        $this->database->insert($this->config->table)->values([
            $this->config->userIdColumn => $userId,
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

        $row = $this->database->select()->from($this->config->table)
            ->where($this->config->tokenColumn, self::hash($plainToken))->run()->fetch();

        if ($row === false) {
            return null;
        }

        $token = $this->hydrate($row);
        $now = $this->dateTimeFactory->now();

        if ($token->expiresAt <= $now) {
            $this->database->delete($this->config->table)
                ->where($this->config->idColumn, $token->id)->run();

            return null;
        }

        $affectedRows = $this->database->delete($this->config->table)
            ->where($this->config->idColumn, $token->id)
            ->where($this->config->expiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->run();

        return $affectedRows === 0 ? null : $token;
    }

    #[\Override]
    public function revoke(string $plainToken): void
    {
        if (!self::validToken($plainToken)) {
            return;
        }

        $this->database->delete($this->config->table)
            ->where($this->config->tokenColumn, self::hash($plainToken))->run();
    }

    #[\Override]
    public function revokeForSession(string $sessionId): void
    {
        $this->revokeForSessions([$sessionId]);
    }

    #[\Override]
    public function revokeForSessions(iterable $sessionIds): void
    {
        $ids = [];

        foreach ($sessionIds as $sessionId) {
            if (!is_string($sessionId)) {
                throw new \InvalidArgumentException('Every session ID must be a string.');
            }

            self::assertId($sessionId, 'Session ID');
            $ids[$sessionId] = true;
        }

        foreach (array_chunk(array_keys($ids), self::REVOKE_CHUNK_SIZE) as $chunk) {
            $this->database->delete($this->config->table)
                ->where($this->config->sessionIdColumn, 'IN', $chunk)->run();
        }
    }

    #[\Override]
    public function revokeAllForUser(int|string $userId, ?string $exceptSessionId = null): void
    {
        self::assertSubjectId($userId);
        $delete = $this->database->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId);

        if ($exceptSessionId !== null) {
            self::assertId($exceptSessionId, 'Session ID');
            $delete->where(function ($query) use ($exceptSessionId): void {
                $query
                    ->where($this->config->sessionIdColumn, '!=', $exceptSessionId)
                    ->orWhere($this->config->sessionIdColumn, null);
            });
        }

        $delete->run();
    }

    #[\Override]
    public function updateSessionId(string $oldSessionId, string $newSessionId): void
    {
        self::assertId($oldSessionId, 'Old session ID');
        self::assertId($newSessionId, 'New session ID');
        $this->database->update($this->config->table)
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->values([$this->config->sessionIdColumn => $newSessionId])->run();
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
        $rows = $this->database->select($this->config->idColumn)
            ->from($this->config->table)
            ->where($this->config->expiresAtColumn, '<=', $now)
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = array_map(
            fn(array $row): int => (int) $row[$this->config->idColumn],
            $rows,
        );
        $deleted = 0;

        foreach (array_chunk($ids, self::REVOKE_CHUNK_SIZE) as $chunk) {
            $deleted += $this->database->delete($this->config->table)
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

    private static function assertSubjectId(int|string $userId): void
    {
        if (is_string($userId) && ($userId === '' || strlen($userId) > self::MAX_ID_LENGTH)) {
            throw new \InvalidArgumentException('Remember-me subject ID is invalid.');
        }
    }

    private static function assertId(string $value, string $label): void
    {
        if ($value === '' || strlen($value) > self::MAX_ID_LENGTH) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): RememberMeToken
    {
        return new RememberMeToken(
            id: (int) $row[$this->config->idColumn],
            userId: $row[$this->config->userIdColumn],
            sessionId: isset($row[$this->config->sessionIdColumn])
                ? (string) $row[$this->config->sessionIdColumn]
                : null,
            expiresAt: $this->dateTimeFactory->parse($row[$this->config->expiresAtColumn]),
            createdAt: $this->dateTimeFactory->parse($row[$this->config->createdAtColumn]),
        );
    }
}
