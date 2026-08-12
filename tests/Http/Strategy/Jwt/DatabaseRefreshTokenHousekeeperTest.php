<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenHousekeeper;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseRefreshTokenHousekeeperTest extends TestCase
{
    private const string TOKEN_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string TOKEN_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const string FAMILY_A = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    private const string FAMILY_B = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';

    public function testCleanupRemovesOnlyFamiliesWhoseEntireHistoryExpired(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $store->storeInitial(new RefreshToken(self::TOKEN_A, $subject, self::FAMILY_A, 900));
        $store->storeInitial(new RefreshToken(self::TOKEN_B, $subject, self::FAMILY_B, 2000));

        $deleted = (new DatabaseRefreshTokenHousekeeper($database))->cleanup(1000, 10);

        self::assertSame(1, $deleted);
        self::assertSame(
            [self::FAMILY_B],
            array_column(
                $database->select('family_id')->from('refresh_token_families')->run()->fetchAll(),
                'family_id',
            ),
        );
        self::assertSame(
            1,
            $database->select()->from('refresh_tokens')->count(),
        );
    }

    public function testCleanupIsBoundedByFamilies(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $store->storeInitial(new RefreshToken(self::TOKEN_A, $subject, self::FAMILY_A, 900));
        $store->storeInitial(new RefreshToken(self::TOKEN_B, $subject, self::FAMILY_B, 900));

        self::assertSame(
            1,
            (new DatabaseRefreshTokenHousekeeper($database))->cleanup(1000, 1),
        );
        self::assertSame(1, $database->select()->from('refresh_token_families')->count());
    }

    private static function createSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_token_families (
                family_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                revoked_at INTEGER NULL,
                compromised_at INTEGER NULL,
                lock_nonce TEXT NOT NULL
            )
            SQL);
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER NULL,
                revoked_at INTEGER NULL,
                FOREIGN KEY (family_id) REFERENCES refresh_token_families(family_id)
            )
            SQL);
    }
}
