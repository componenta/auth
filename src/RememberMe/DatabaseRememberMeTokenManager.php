<?php

declare(strict_types=1);

namespace Componenta\Auth\RememberMe;

use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

final readonly class DatabaseRememberMeTokenManager implements RememberMeTokenManagerInterface
{
    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private DatabaseRememberMeTokenManagerConfig $config = new DatabaseRememberMeTokenManagerConfig(),
    ) {}

    public function create(int|string $userId, ?string $sessionId = null): string
    {
        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();

        $this->database
            ->insert($this->config->table)
            ->values([
                $this->config->userIdColumn => $userId,
                $this->config->sessionIdColumn => $sessionId,
                $this->config->tokenColumn => $this->hash($plainToken),
                $this->config->expiresAtColumn => $now->modify("+{$this->config->ttl} seconds")->format($this->config->dateFormat),
                $this->config->createdAtColumn => $now->format($this->config->dateFormat),
            ])
            ->run();

        return $plainToken;
    }

    public function consume(string $plainToken): ?RememberMeToken
    {
        $hash = $this->hash($plainToken);

        $row = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->tokenColumn, $hash)
            ->run()
            ->fetch();

        if ($row === false) {
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
            ->run();

        if ($affectedRows === 0) {
            return null;
        }

        return $token;
    }

    public function revoke(string $plainToken): void
    {
        $this->database
            ->delete($this->config->table)
            ->where($this->config->tokenColumn, $this->hash($plainToken))
            ->run();
    }

    public function revokeForSession(string $sessionId): void
    {
        $this->database
            ->delete($this->config->table)
            ->where($this->config->sessionIdColumn, $sessionId)
            ->run();
    }

    public function revokeAllForUser(int|string $userId, ?string $exceptSessionId = null): void
    {
        $delete = $this->database
            ->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId);

        if ($exceptSessionId !== null) {
            $delete->where($this->config->sessionIdColumn, '!=', $exceptSessionId);
        }

        $delete->run();
    }

    public function updateSessionId(string $oldSessionId, string $newSessionId): void
    {
        $this->database
            ->update($this->config->table)
            ->where($this->config->sessionIdColumn, $oldSessionId)
            ->values([
                $this->config->sessionIdColumn => $newSessionId,
            ])
            ->run();
    }

    public function cleanup(): void
    {
        $now = $this->dateTimeFactory->now();

        $this->database
            ->delete($this->config->table)
            ->where($this->config->expiresAtColumn, '<', $now->format($this->config->dateFormat))
            ->run();
    }

    private function hash(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }

    /**
     * @param array<string, mixed> $row
     */
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
