<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

final readonly class DatabaseRememberMeTokenManager implements RememberMeTokenManagerInterface
{
    private const int REVOKE_CHUNK_SIZE = 500;

    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private DatabaseRememberMeTokenManagerConfig $config = new DatabaseRememberMeTokenManagerConfig(),
    ) {}

    public function create(int|string $userId, ?string $sessionId = null): string
    {
        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();

        $this->database->insert($this->config->table)->values([
            $this->config->userIdColumn => $userId,
            $this->config->sessionIdColumn => $sessionId,
            $this->config->tokenColumn => $this->hash($plainToken),
            $this->config->expiresAtColumn => $now->modify("+{$this->config->ttl} seconds")->format($this->config->dateFormat),
            $this->config->createdAtColumn => $now->format($this->config->dateFormat),
        ])->run();

        return $plainToken;
    }

    public function consume(string $plainToken): ?RememberMeToken
    {
        $row = $this->database->select()->from($this->config->table)
            ->where($this->config->tokenColumn, $this->hash($plainToken))->run()->fetch();

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
            ->where($this->config->idColumn, $token->id)->run();

        return $affectedRows === 0 ? null : $token;
    }

    public function revoke(string $plainToken): void
    {
        $this->database->delete($this->config->table)
            ->where($this->config->tokenColumn, $this->hash($plainToken))->run();
    }

    public function revokeForSession(string $sessionId): void
    {
        $this->revokeForSessions([$sessionId]);
    }

    public function revokeForSessions(iterable $sessionIds): void
    {
        $ids = [];
        foreach ($sessionIds as $sessionId) {
            if ($sessionId !== '') {
                $ids[$sessionId] = true;
            }
        }

        foreach (array_chunk(array_keys($ids), self::REVOKE_CHUNK_SIZE) as $chunk) {
            $this->database->delete($this->config->table)
                ->where($this->config->sessionIdColumn, 'IN', $chunk)->run();
        }
    }

    public function revokeAllForUser(int|string $userId, ?string $exceptSessionId = null): void
    {
        $delete = $this->database->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId);

        if ($exceptSessionId !== null) {
            $delete->where(function ($query) use ($exceptSessionId): void {
                $query
                    ->orWhere($this->config->sessionIdColumn, '!=', $exceptSessionId)
                    ->orWhere($this->config->sessionIdColumn, null);
            });
        }

        $delete->run();
    }

    public function updateSessionId(string $oldSessionId, string $newSessionId): void
    {
        $this->database->update($this->config->table)
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->values([$this->config->sessionIdColumn => $newSessionId])->run();
    }

    public function cleanup(): void
    {
        $now = $this->dateTimeFactory->now();
        $this->database->delete($this->config->table)
            ->where($this->config->expiresAtColumn, '<', $now->format($this->config->dateFormat))->run();
    }

    private function hash(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): RememberMeToken
    {
        return new RememberMeToken(
            id: (int) $row[$this->config->idColumn],
            userId: $row[$this->config->userIdColumn],
            sessionId: isset($row[$this->config->sessionIdColumn]) ? (string) $row[$this->config->sessionIdColumn] : null,
            expiresAt: $this->dateTimeFactory->parse($row[$this->config->expiresAtColumn]),
            createdAt: $this->dateTimeFactory->parse($row[$this->config->createdAtColumn]),
        );
    }
}
