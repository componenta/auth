<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Http\Strategy\Otp\CodeVerificationStatus;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Auth\Token\TokenConfig;
use Componenta\Auth\Token\TokenManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseMySql84IntegrationTest extends TestCase
{
    private const string TOKEN_A =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string TOKEN_B =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const string TOKEN_C =
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    private const string FAMILY =
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
    private const string OTP_HMAC_KEY =
        'componenta-auth-mysql-otp-test-key-32-bytes';

    public function testOneTimeTokenReplacementUsesMySqlUpsert(): void
    {
        $database = self::database();
        self::resetSchema($database);
        $database->execute(<<<'SQL'
            CREATE TABLE one_time_tokens (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
                token CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                used_at DATETIME NULL,
                created_at DATETIME NOT NULL,
                INDEX idx_one_time_expiry (expires_at),
                INDEX idx_one_time_used (used_at)
            ) ENGINE=InnoDB
            SQL);
        $manager = new TokenManager(
            $database,
            new FrozenClock(1000, 'Europe/Copenhagen'),
            new TokenConfig('one_time_tokens', 'magic_link'),
        );
        $subjectId = self::subjectId();

        $first = $manager->replaceForSubject($subjectId);
        $second = $manager->replaceForSubject($subjectId);

        self::assertNotSame($first, $second);
        self::assertNull($manager->find($first));
        self::assertNotNull($manager->find($second));
        self::assertTrue($manager->consume($second));
        self::assertFalse($manager->consume($second));
    }

    public function testOtpReplacementAndConsumptionUseMySqlUpsertAndCas(): void
    {
        $database = self::database();
        self::resetSchema($database);
        $database->execute(<<<'SQL'
            CREATE TABLE otp_codes (
                destination VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
                user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                challenge_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
                verifier CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                expires_at BIGINT UNSIGNED NOT NULL,
                attempts INT UNSIGNED NOT NULL,
                INDEX idx_otp_expiry (expires_at)
            ) ENGINE=InnoDB
            SQL);
        $store = new DatabaseCodeStore($database, self::OTP_HMAC_KEY);
        $subjectId = self::subjectId();

        $store->store(new StoredCode(
            $subjectId,
            '123456',
            'mail@example.com',
            2000,
        ));
        $store->store(new StoredCode(
            $subjectId,
            '654321',
            'mail@example.com',
            3000,
        ));

        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                'mail@example.com',
                '123456',
                1000,
                5,
            )->status,
        );
        self::assertSame(
            CodeVerificationStatus::Verified,
            $store->verifyAndConsume(
                'mail@example.com',
                '654321',
                1001,
                5,
            )->status,
        );
        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                'mail@example.com',
                '654321',
                1002,
                5,
            )->status,
        );
    }

    public function testRefreshRotationAndReplayUseMySqlTransactionSemantics(): void
    {
        $database = self::database();
        self::resetSchema($database);
        self::createRefreshSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = self::subjectId();
        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            $subjectId,
            self::FAMILY,
            2000,
        ));

        self::assertSame(
            RefreshTokenRotationStatus::Rotated,
            $store->rotateAtomically(
                self::TOKEN_A,
                self::TOKEN_B,
                3000,
                1000,
            )->status,
        );
        self::assertSame(
            RefreshTokenRotationStatus::Reused,
            $store->rotateAtomically(
                self::TOKEN_A,
                self::TOKEN_C,
                4000,
                1001,
            )->status,
        );
        self::assertSame(
            RefreshTokenRotationStatus::Reused,
            $store->rotateAtomically(
                self::TOKEN_B,
                self::TOKEN_C,
                4000,
                1002,
            )->status,
        );
    }

    public function testSessionCleanupPreservesReplacementLineageOnMySql(): void
    {
        $database = self::database();
        self::resetSchema($database);
        $database->execute(<<<'SQL'
            CREATE TABLE sessions (
                id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
                user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                ip VARCHAR(45) NOT NULL,
                user_agent VARCHAR(1024) NOT NULL,
                expires_at DATETIME NOT NULL,
                absolute_expires_at DATETIME NOT NULL,
                regenerate_at DATETIME NOT NULL,
                replaced_by VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
                created_at DATETIME NOT NULL,
                last_active_at DATETIME NOT NULL,
                attributes TEXT NOT NULL,
                INDEX idx_session_subject (user_id),
                INDEX idx_session_replaced (replaced_by),
                INDEX idx_session_cleanup_idle (replaced_by, expires_at),
                INDEX idx_session_cleanup_absolute (absolute_expires_at)
            ) ENGINE=InnoDB
            SQL);
        $manager = self::sessionManager($database, 1000);
        $old = $manager->create(self::subjectId(), [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'mysql-lineage-test',
        ]);
        $new = $manager->regenerate($old->id);
        $afterGrace = self::sessionManager($database, 1040);

        self::assertSame(0, $afterGrace->cleanup());
        self::assertSame(2, $database->select()->from('sessions')->count());
        self::assertTrue($afterGrace->exists($new->id));

        $afterGrace->terminate($old->id);

        self::assertSame(0, $database->select()->from('sessions')->count());
    }

    private static function database(): DatabaseInterface
    {
        if (!MySqlDatabaseFixture::available()) {
            self::markTestSkipped(
                'AUTH_TEST_MYSQL_DSN and pdo_mysql are required for MySQL integration tests.',
            );
        }

        return MySqlDatabaseFixture::create();
    }

    private static function sessionManager(
        DatabaseInterface $database,
        int $timestamp,
    ): DatabaseSessionManager {
        return new DatabaseSessionManager(
            $database,
            new SessionIdGenerator(),
            new FrozenClock($timestamp, 'UTC'),
            new EventDispatcher(new PriorityListenerProvider()),
            new DatabaseSessionManagerConfig(),
        );
    }

    private static function createRefreshSchema(DatabaseInterface $database): void
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
                CONSTRAINT fk_refresh_family
                    FOREIGN KEY (family_id)
                    REFERENCES refresh_token_families(family_id)
            ) ENGINE=InnoDB
            SQL);
    }

    private static function subjectId(): \Componenta\Identity\UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    private static function resetSchema(DatabaseInterface $database): void
    {
        $database->execute('SET FOREIGN_KEY_CHECKS = 0');

        foreach ([
            'refresh_tokens',
            'refresh_token_families',
            'otp_codes',
            'one_time_tokens',
            'sessions',
        ] as $table) {
            $database->execute('DROP TABLE IF EXISTS ' . $table);
        }

        $database->execute('SET FOREIGN_KEY_CHECKS = 1');
    }
}
