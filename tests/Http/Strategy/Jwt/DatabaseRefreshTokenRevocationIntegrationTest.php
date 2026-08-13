<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseRefreshTokenRevocationIntegrationTest extends TestCase
{
    private const string TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string SUCCESSOR =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const string RETRY_SUCCESSOR =
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    private const string FAMILY =
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';

    public function testRevocationAfterRotationTerminatesWholeFamilyOnSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
        self::createSqliteSchema($database);

        $this->assertRevocationAfterRotation($database);
    }

    public function testRevocationAfterRotationTerminatesWholeFamilyOnMySql(): void
    {
        if (!MySqlDatabaseFixture::available()) {
            self::markTestSkipped(
                'AUTH_TEST_MYSQL_DSN and pdo_mysql are required for MySQL integration tests.',
            );
        }

        $database = MySqlDatabaseFixture::create();
        self::resetMySqlSchema($database);
        self::createMySqlSchema($database);

        $this->assertRevocationAfterRotation($database);
    }

    private function assertRevocationAfterRotation(DatabaseInterface $database): void
    {
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $store->storeInitial(new RefreshToken(
            self::TOKEN,
            $subjectId,
            self::FAMILY,
            2000,
        ));

        self::assertSame(
            RefreshTokenRotationStatus::Rotated,
            $store->rotateAtomically(
                self::TOKEN,
                self::SUCCESSOR,
                3000,
                1000,
            )->status,
        );

        // Models revocation winning only after a concurrent rotation committed.
        $store->revoke(self::TOKEN, 1001);

        $family = $database
            ->select(['revoked_at', 'compromised_at'])
            ->from('refresh_token_families')
            ->where('family_id', self::FAMILY)
            ->run()
            ->fetch();
        self::assertIsArray($family);
        self::assertSame(1001, $family['revoked_at'] ?? null);
        self::assertNull($family['compromised_at'] ?? null);

        $successor = $database
            ->select('revoked_at')
            ->from('refresh_tokens')
            ->where('token_hash', hash('sha256', self::SUCCESSOR))
            ->run()
            ->fetch();
        self::assertIsArray($successor);
        self::assertSame(1001, $successor['revoked_at'] ?? null);

        self::assertSame(
            RefreshTokenRotationStatus::Invalid,
            $store->rotateAtomically(
                self::SUCCESSOR,
                self::RETRY_SUCCESSOR,
                4000,
                1002,
            )->status,
        );
        self::assertSame(
            0,
            $database
                ->select()
                ->from('refresh_tokens')
                ->where('family_id', self::FAMILY)
                ->where('revoked_at', null)
                ->count(),
        );
    }

    private static function createSqliteSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_token_families (
                family_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
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
                FOREIGN KEY (family_id)
                    REFERENCES refresh_token_families(family_id)
            )
            SQL);
        $database->execute(
            'CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id)',
        );
        $database->execute(
            'CREATE INDEX idx_refresh_tokens_subject ON refresh_tokens(user_id)',
        );
        $database->execute(
            'CREATE INDEX idx_refresh_families_subject ON refresh_token_families(user_id)',
        );
        $database->execute(
            'CREATE INDEX idx_refresh_families_expiry ON refresh_token_families(expires_at)',
        );
    }

    private static function createMySqlSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_token_families (
                family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                expires_at BIGINT UNSIGNED NOT NULL,
                revoked_at BIGINT UNSIGNED NULL,
                compromised_at BIGINT UNSIGNED NULL,
                lock_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                INDEX idx_refresh_family_subject (user_id),
                INDEX idx_refresh_family_expiry (expires_at)
            ) ENGINE=InnoDB
            SQL);
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_tokens (
                token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
                family_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                expires_at BIGINT UNSIGNED NOT NULL,
                consumed_at BIGINT UNSIGNED NULL,
                revoked_at BIGINT UNSIGNED NULL,
                INDEX idx_refresh_token_family (family_id),
                INDEX idx_refresh_token_subject (user_id),
                INDEX idx_refresh_token_expiry (expires_at),
                INDEX idx_refresh_token_family_expiry (family_id, expires_at),
                CONSTRAINT fk_refresh_family_revocation
                    FOREIGN KEY (family_id)
                    REFERENCES refresh_token_families(family_id)
            ) ENGINE=InnoDB
            SQL);
    }

    private static function resetMySqlSchema(DatabaseInterface $database): void
    {
        $database->execute('SET FOREIGN_KEY_CHECKS = 0');
        $database->execute('DROP TABLE IF EXISTS refresh_tokens');
        $database->execute('DROP TABLE IF EXISTS refresh_token_families');
        $database->execute('SET FOREIGN_KEY_CHECKS = 1');
    }
}
