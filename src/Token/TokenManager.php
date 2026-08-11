<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Clock\DateTimeFactoryInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use Cycle\Database\Query\SelectQuery;

final readonly class TokenManager implements TokenManagerInterface
{
    private const int MAX_CLEANUP_LIMIT = 10000;
    private const int DELETE_CHUNK_SIZE = 500;

    public function __construct(
        private DatabaseInterface $database,
        private DateTimeFactoryInterface $dateTimeFactory,
        private TokenConfig $config,
    ) {}

    #[\Override]
    public function replaceForSubject(UuidInterface $subjectId): string
    {
        $plainToken = bin2hex(random_bytes(32));
        $now = $this->dateTimeFactory->now();

        $values = [
            $this->config->subjectIdColumn => $subjectId->toString(),
            $this->config->tokenColumn => self::hash($plainToken),
            $this->config->expiresAtColumn => $now
                ->modify("+{$this->config->ttl} seconds")
                ->format($this->config->dateFormat),
            $this->config->usedAtColumn => null,
            $this->config->createdAtColumn => $now->format($this->config->dateFormat),
        ];

        // One statement, backed by UNIQUE(subject_id), ensures concurrent
        // requests cannot leave two active challenges for the same subject.
        $this->database
            ->insert($this->config->table)
            ->values($values)
            ->onConflict(OnConflict::target($this->config->subjectIdColumn)
                ->doUpdate([
                    $this->config->tokenColumn,
                    $this->config->expiresAtColumn,
                    $this->config->usedAtColumn,
                    $this->config->createdAtColumn,
                ]))
            ->run();

        return $plainToken;
    }

    #[\Override]
    public function find(string $plainToken): ?Token
    {
        if (!self::validToken($plainToken)) {
            return null;
        }

        $row = $this->database
            ->select()
            ->from($this->config->table)
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->run()
            ->fetch();

        return is_array($row) ? $this->hydrate($row) : null;
    }

    #[\Override]
    public function consume(string $plainToken): bool
    {
        if (!self::validToken($plainToken)) {
            return false;
        }

        $now = $this->dateTimeFactory->now();
        $formattedNow = $now->format($this->config->dateFormat);
        $affected = $this->database
            ->update($this->config->table)
            ->values([$this->config->usedAtColumn => $formattedNow])
            ->where($this->config->tokenColumn, self::hash($plainToken))
            ->where($this->config->usedAtColumn, null)
            ->where($this->config->expiresAtColumn, '>', $formattedNow)
            ->run();

        return $affected > 0;
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
        $expiredOrUsed = function (mixed $query) use ($now): void {
            if (!$query instanceof SelectQuery) {
                throw new \LogicException('Cycle must provide a SelectQuery to the predicate.');
            }

            $query
                ->where($this->config->expiresAtColumn, '<=', $now)
                ->orWhere($this->config->usedAtColumn, '!=', null);
        };
        $rows = $this->database
            ->select($this->config->idColumn)
            ->from($this->config->table)
            ->where($expiredOrUsed)
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

        foreach (array_chunk($ids, self::DELETE_CHUNK_SIZE) as $chunk) {
            $delete = $this->database
                ->delete($this->config->table)
                ->where($this->config->idColumn, 'IN', $chunk);
            $delete->where(function (mixed $query) use ($now): void {
                if (!$query instanceof \Cycle\Database\Query\DeleteQuery) {
                    throw new \LogicException(
                        'Cycle must provide a DeleteQuery to the predicate.',
                    );
                }

                $query
                    ->where($this->config->expiresAtColumn, '<=', $now)
                    ->orWhere($this->config->usedAtColumn, '!=', null);
            });
            $deleted += $delete->run();
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

    /** @param array<array-key, mixed> $row */
    private function hydrate(array $row): Token
    {
        $usedAt = $row[$this->config->usedAtColumn] ?? null;

        return new Token(
            id: self::intValue($row, $this->config->idColumn),
            subjectId: Uuid::fromString(self::stringValue(
                $row,
                $this->config->subjectIdColumn,
            )),
            expiresAt: $this->dateTimeFactory->parse(self::stringValue(
                $row,
                $this->config->expiresAtColumn,
            )),
            usedAt: $usedAt === null
                ? null
                : $this->dateTimeFactory->parse(self::stringValue(
                    $row,
                    $this->config->usedAtColumn,
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
