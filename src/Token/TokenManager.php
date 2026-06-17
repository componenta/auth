<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

/**
 * Database-backed one-time token manager.
 *
 * Tokens are one-time use: generated as random bytes, stored as SHA-256 hash.
 * The plain token is sent to the user; the hash is stored in the database.
 * Consuming a token is atomic (single UPDATE with WHERE used_at IS NULL).
 */
final readonly class TokenManager implements TokenManagerInterface
{
    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private TokenConfig $config,
    ) {}

    #[\Override]
    public function generate(string $userId): string
    {
        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();

        $this->database
            ->insert($this->config->table)
            ->values([
                $this->config->userIdColumn => $userId,
                $this->config->tokenColumn => $this->hash($plainToken),
                $this->config->expiresAtColumn => $now->modify("+{$this->config->ttl} seconds")->format($this->config->dateFormat),
                $this->config->createdAtColumn => $now->format($this->config->dateFormat),
            ])
            ->run();

        return $plainToken;
    }

    #[\Override]
    public function find(string $plainToken): ?Token
    {
        $row = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->tokenColumn, $this->hash($plainToken))
            ->run()
            ->fetch();

        if ($row === false) {
            return null;
        }

        return $this->hydrate($row);
    }

    #[\Override]
    public function consume(string $plainToken): bool
    {
        $now = $this->dateTimeFactory->now();

        $affected = $this->database
            ->update($this->config->table)
            ->values([
                $this->config->usedAtColumn => $now->format($this->config->dateFormat),
            ])
            ->where($this->config->tokenColumn, $this->hash($plainToken))
            ->where($this->config->usedAtColumn, null)
            ->where($this->config->expiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->run();

        return $affected > 0;
    }

    #[\Override]
    public function revokeForUser(string $userId): void
    {
        $this->database
            ->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId)
            ->run();
    }

    #[\Override]
    public function cleanup(): void
    {
        $now = $this->dateTimeFactory->now();

        $this->database
            ->delete($this->config->table)
            ->where(function ($select) use ($now): void {
                $select
                    ->orWhere($this->config->expiresAtColumn, '<', $now->format($this->config->dateFormat))
                    ->orWhere($this->config->usedAtColumn, '!=', null);
            })
            ->run();
    }

    private function hash(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): Token
    {
        return new Token(
            id: (int) $row[$this->config->idColumn],
            userId: (string) $row[$this->config->userIdColumn],
            expiresAt: $this->dateTimeFactory->parse($row[$this->config->expiresAtColumn]),
            usedAt: isset($row[$this->config->usedAtColumn]) ? $this->dateTimeFactory->parse($row[$this->config->usedAtColumn]) : null,
            createdAt: $this->dateTimeFactory->parse($row[$this->config->createdAtColumn]),
        );
    }
}
