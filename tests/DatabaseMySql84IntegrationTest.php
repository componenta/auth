<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Http\Strategy\Otp\CodeVerificationStatus;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
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
                user_id CHAR(36) NOT NULL UNIQUE,
                token CHAR(64) NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                used_at DATETIME NULL,
                created_at DATETIME NOT NULL
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
                destination VARCHAR(320) NOT NULL PRIMARY KEY,
                user_id CHAR(36) NOT NULL,
                challenge_id CHAR(32) NOT NULL,
                verifier CHAR(64) NOT NULL,
                expires_at BIGINT UNSIGNED NOT NULL,
                attempts INT UNSIGNED NOT NULL
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
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_token_families (
                family_id CHAR(64) NOT NULL PRIMARY KEY,
                user_id CHAR(36) NOT NULL,
                revoked_at BIGINT UNSIGNED NULL,
                compromised_at BIGINT UNSIGNED NULL,
                lock_nonce CHAR(32) NOT NULL,
                INDEX idx_refresh_family_subject (user_id)
            ) ENGINE=InnoDB
            SQL);
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_tokens (
                token_hash CHAR(64) NOT NULL PRIMARY KEY,
                family_id CHAR(64) NOT NULL,
                user_id CHAR(36) NOT NULL,
                expires_at BIGINT UNSIGNED NOT NULL,
                consumed_at BIGINT UNSIGNED NULL,
                revoked_at BIGINT UNSIGNED NULL,
                INDEX idx_refresh_token_family (family_id),
                INDEX idx_refresh_token_subject (user_id),
                CONSTRAINT fk_refresh_family
                    FOREIGN KEY (family_id)
                    REFERENCES refresh_token_families(family_id)
            ) ENGINE=InnoDB
            SQL);
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

    private static function database(): DatabaseInterface
    {
        if (!MySqlDatabaseFixture::available()) {
            self::markTestSkipped(
                'AUTH_TEST_MYSQL_DSN and pdo_mysql are required for MySQL integration tests.',
            );
        }

        return MySqlDatabaseFixture::create();
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
        ] as $table) {
            $database->execute('DROP TABLE IF EXISTS ' . $table);
        }

        $database->execute('SET FOREIGN_KEY_CHECKS = 1');
    }
}
