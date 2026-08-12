<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Cycle\Database\DatabaseInterface;
use Cycle\Database\Injection\Expression;
use Cycle\Database\Query\SelectQuery;

/** Bounded cleanup for refresh families whose complete token history has expired. */
final readonly class DatabaseRefreshTokenHousekeeper
{
    private const int LOCK_NONCE_BYTES = 16;
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
        $ids = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $familyId = $row[$this->config->familyIdColumn] ?? null;
            if (is_string($familyId) && $familyId !== '') {
                $ids[$familyId] = true;
            }
        }

        if ($ids === []) {
            return 0;
        }

        $familyIds = array_keys($ids);
        sort($familyIds, SORT_STRING);

        return $this->database->transaction(
            function (DatabaseInterface $database) use ($familyIds, $now): int {
                $deleted = 0;

                foreach ($familyIds as $familyId) {
                    // The family row is the same serialization point used by
                    // rotation and revocation. Once claimed, no successor can
                    // be inserted until the expiry predicate is rechecked.
                    $claimed = $database
                        ->update($this->config->familyTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->values([
                            $this->config->lockNonceColumn => self::lockNonce(),
                        ])
                        ->run();

                    if ($claimed !== 1) {
                        continue;
                    }

                    $query = $database->select($this->config->familyIdColumn)->withDriver(
                        $database->getDriver(DatabaseInterface::WRITE),
                        $database->getPrefix(),
                    );

                    if (!$query instanceof SelectQuery) {
                        throw new \LogicException(
                            'Cycle must preserve SelectQuery when pinning the write driver.',
                        );
                    }

                    $active = $query
                        ->from($this->config->tokenTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->where($this->config->expiresAtColumn, '>', $now)
                        ->limit(1)
                        ->run()
                        ->fetch();

                    if (is_array($active)) {
                        continue;
                    }

                    $database
                        ->delete($this->config->tokenTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->run();

                    $deleted += $database
                        ->delete($this->config->familyTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->run();
                }

                return $deleted;
            },
        );
    }

    private static function lockNonce(): string
    {
        return bin2hex(random_bytes(self::LOCK_NONCE_BYTES));
    }
}
