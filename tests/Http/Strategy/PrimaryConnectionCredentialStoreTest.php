<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Http\Strategy\Otp\CodeVerificationStatus;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

/** Proves credential-state reads never fall through to a lagging replica. */
final class PrimaryConnectionCredentialStoreTest extends TestCase
{
    private const string REFRESH_TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string REFRESH_SUCCESSOR =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const string REFRESH_FAMILY =
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    private const string OTP_HMAC_KEY =
        'componenta-auth-primary-read-test-key-32-bytes';

    public function testRefreshRotationReadsSecurityStateFromPrimary(): void
    {
        self::requireSqlite();
        $database = self::splitDatabase();
        self::createRefreshSchema($database);
        $store = new DatabaseRefreshTokenStore($database);

        $store->storeInitial(new RefreshToken(
            self::REFRESH_TOKEN,
            self::subjectId(),
            self::REFRESH_FAMILY,
            2000,
        ));

        $result = $store->rotateAtomically(
            self::REFRESH_TOKEN,
            self::REFRESH_SUCCESSOR,
            3000,
            1000,
        );

        self::assertSame(RefreshTokenRotationStatus::Rotated, $result->status);
        self::assertSame(self::REFRESH_SUCCESSOR, $result->token?->id);
    }

    public function testOtpVerificationReadsSecurityStateFromPrimary(): void
    {
        self::requireSqlite();
        $database = self::splitDatabase();
        self::createOtpSchema($database);
        $store = new DatabaseCodeStore($database, self::OTP_HMAC_KEY);

        $store->store(new StoredCode(
            self::subjectId(),
            '123456',
            'mail@example.com',
            2000,
        ));

        $result = $store->verifyAndConsume(
            'mail@example.com',
            '123456',
            1000,
            5,
        );

        self::assertSame(CodeVerificationStatus::Verified, $result->status);
        self::assertNotNull($result->subjectId);
        self::assertTrue(self::subjectId()->equals($result->subjectId));
    }

    private static function splitDatabase(): DatabaseInterface
    {
        $write = SqliteDatabaseFixture::create();
        $read = SqliteDatabaseFixture::create();

        return new Database(
            name: 'split-auth-test',
            prefix: '',
            driver: $write->getDriver(DatabaseInterface::WRITE),
            readDriver: $read->getDriver(DatabaseInterface::WRITE),
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped(
                'pdo_sqlite is required for storage integration tests.',
            );
        }
    }

    private static function subjectId(): \Componenta\Identity\UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    private static function createRefreshSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE refresh_token_families (
                family_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
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
                revoked_at INTEGER NULL
            )
            SQL);
    }

    private static function createOtpSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE otp_codes (
                destination TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                verifier TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL
            )
            SQL);
    }
}
