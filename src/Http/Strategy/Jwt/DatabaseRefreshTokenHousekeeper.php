<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Cycle\Database\DatabaseInterface;
use Cycle\Database\Injection\Expression;
use Cycle\Database\Query\SelectQuery;

/** Bounded cleanup for refresh families whose complete token history has expired. */
final readonly class DatabaseRefreshTokenHousekeeper
{
    private const int MAX_CLEANUP_LIMIT = 10000;

    public function __construct(
        private DatabaseInterface $database,
        private DatabaseRefreshTokenStoreConfig $config = new DatabaseRefreshTokenStoreConfig(),
    ) {}

    /** Removes at most $limit terminally expired families and returns family rows removed. */
    public function cleanup(int $now, int $limit = 1000): int
    {
        if ($now < 1) {
            throw new \InvalidArgumentException(
                'Refresh cleanup time must be positive.',
            );
        }

        if ($limit < 1 || $limit > self::MAX_CLEANUP_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'Refresh cleanup limit must be between 1 and %d.',
                self::MAX_CLEANUP_LIMIT,
            ));
        }

        $rows = $this->database
            ->select($this->config->familyIdColumn)
            ->from($this->config->tokenTable)
            ->groupBy($this->config->familyIdColumn)
            ->having(
                new Expression('MAX(' . $this->config->expiresAtColumn . ')'),
                '<=',
                $now,
            )
            ->limit($limit)
            ->run()
            ->fetchAll();
        $familyIds = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $familyId = $row[$this->config->familyIdColumn] ?? null;
            if (is_string($familyId) && $familyId !== '') {
                $familyIds[$familyId] = true;
            }
        }

        if ($familyIds === []) {
            return 0;
        }

        $ids = array_keys($familyIds);
        $query = $this->database->select($this->config->familyIdColumn)->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        );

        if (!$query instanceof SelectQuery) {
            throw new \LogicException(
                'Cycle must preserve SelectQuery when pinning the write driver.',
            );
        }

        $active = $query
            ->from($this->config->tokenTable)
            ->where($this->config->familyIdColumn, 'IN', $ids)
            ->where($this->config->expiresAtColumn, '>', $now)
            ->distinct()
            ->run()
            ->fetchAll();

        foreach ($active as $row) {
            if (!is_array($row)) {
                continue;
            }

            $familyId = $row[$this->config->familyIdColumn] ?? null;
            if (is_string($familyId)) {
                unset($familyIds[$familyId]);
            }
        }

        $ids = array_keys($familyIds);
        if ($ids === []) {
            return 0;
        }

        return $this->database->transaction(
            function (DatabaseInterface $database) use ($ids): int {
                $database
                    ->delete($this->config->tokenTable)
                    ->where($this->config->familyIdColumn, 'IN', $ids)
                    ->run();

                return $database
                    ->delete($this->config->familyTable)
                    ->where($this->config->familyIdColumn, 'IN', $ids)
                    ->run();
            },
        );
    }
}
