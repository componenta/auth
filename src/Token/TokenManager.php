<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Clock\DateTimeFactoryInterface;
use Cycle\Database\DatabaseInterface;

final readonly class TokenManager implements TokenManagerInterface
{
    private const int MAX_SUBJECT_ID_LENGTH = 512;
    private const int MAX_CLEANUP_LIMIT = 10000;
    private const int DELETE_CHUNK_SIZE = 500;

    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private TokenConfig $config,
    ) {}

    #[\Override]
    public function generate(string $userId): string
    {
        self::assertSubjectId($userId);
        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();
        $this->database->insert($this->config->table)->values([
            $this->config->userIdColumn => $userId,
            $this->config->tokenColumn => self::hash($plainToken),
            $this->config->expiresAtColumn => $now
                ->modify("+{$this->config->ttl} seconds")
                ->format($this->config->dateFormat),
            $this->config->createdAtColumn => $now->format($this->config->dateFormat),
        ])->run();

        return $plainToken;
    }

    #[\Override]
    public function find(string $plainToken): ?Token
    {
        if (!self::validToken($plainToken)) {
            return null;
        }

        $row = $this->database->select()->from($this->config->table)
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->run()->fetch();

        return $row === false ? null : $this->hydrate($row);
    }

    #[\Override]
    public function consume(string $plainToken): bool
    {
        if (!self::validToken($plainToken)) {
            return false;
        }

        $now = $this->dateTimeFactory->now();
        $affected = $this->database->update($this->config->table)
            ->values([$this->config->usedAtColumn => $now->format($this->config->dateFormat)])
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->where($this->config->usedAtColumn, null)
            ->where($this->config->expiresAtColumn, '>', $now->format($this->config->dateFormat))
            ->run();

        return $affected > 0;
    }

    #[\Override]
    public function revokeForUser(string $userId): void
    {
        self::assertSubjectId($userId);
        $this->database->delete($this->config->table)
            ->where($this->config->userIdColumn, $userId)->run();
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'Token cleanup limit must be between 1 and %d.',
                self::MAX_CLEANUP_LIMIT,
            ));
        }

        $now = $this->dateTimeFactory->now()->format($this->config->dateFormat);
        $expiredOrUsed = function ($query) use ($now): void {
            $query
                ->where($this->config->expiresAtColumn, '<=', $now)
                ->orWhere($this->config->usedAtColumn, '!=', null);
        };
        $rows = $this->database->select($this->config->idColumn)
            ->from($this->config->table)
            ->where($expiredOrUsed)
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = array_map(
            fn(array $row): int => (int) $row[$this->config->idColumn],
            $rows,
        );
        $deleted = 0;

        foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
            $deleted += $this->database->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $chunk)
                ->where($expiredOrUsed)
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

    private static function assertSubjectId(string $userId): void
    {
        if ($userId === '' || strlen($userId) > self::MAX_SUBJECT_ID_LENGTH) {
            throw new \InvalidArgumentException('Token subject ID is invalid.');
        }
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): Token
    {
        return new Token(
            id: (int) $row[$this->config->idColumn],
            userId: (string) $row[$this->config->userIdColumn],
            expiresAt: $this->dateTimeFactory->parse($row[$this->config->expiresAtColumn]),
            usedAt: isset($row[$this->config->usedAtColumn])
                ? $this->dateTimeFactory->parse($row[$this->config->usedAtColumn])
                : null,
            createdAt: $this->dateTimeFactory->parse($row[$this->config->createdAtColumn]),
        );
    }
}
