<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Http\Strategy\Otp\CodeVerificationStatus;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Token\TokenConfig;
use Componenta\Auth\Token\TokenManager;
use Componenta\Clock\FrozenClock;
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

    public function testSessionAuthenticationStateReadsFromPrimary(): void
    {
        self::requireSqlite();
        $database = self::splitDatabase();
        self::createSessionSchema($database);
        $manager = new DatabaseSessionManager(
            $database,
            new SessionIdGenerator(),
            new FrozenClock(1000, 'UTC'),
            new EventDispatcher(new PriorityListenerProvider()),
        );
        $subjectId = self::subjectId();
        $session = $manager->create($subjectId, [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'primary-read-test',
        ]);

        self::assertTrue($manager->exists($session->id));
        self::assertSame($session->id, $manager->find($session->id)?->id);
        self::assertFalse($manager->all($subjectId)->empty);
    }

    public function testRememberMeRotationReadsFromPrimary(): void
    {
        self::requireSqlite();
        $database = self::splitDatabase();
        self::createRememberMeSchema($database);
        $manager = new DatabaseRememberMeTokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
        );
        $plainToken = $manager->create(self::subjectId(), 'session-id');

        $rotation = $manager->rotate($plainToken);

        self::assertNotNull($rotation);
        self::assertSame('session-id', $rotation->previousSessionId);
        self::assertNull($manager->rotate($plainToken));
    }

    public function testOneTimeTokenLookupReadsFromPrimary(): void
    {
        self::requireSqlite();
        $database = self::splitDatabase();
        self::createOneTimeTokenSchema($database);
        $manager = new TokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
            new TokenConfig('one_time_tokens', 'primary_read_test'),
        );
        $plainToken = $manager->replaceForSubject(self::subjectId());

        self::assertNotNull($manager->find($plainToken));
        self::assertTrue($manager->consume($plainToken));
        self::assertFalse($manager->consume($plainToken));
    }

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

        self::assertNotNull($store->findActiveSubject(
            self::REFRESH_TOKEN,
            1000,
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

    private static function createSessionSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                absolute_expires_at TEXT NOT NULL,
                regenerate_at TEXT NOT NULL,
                replaced_by TEXT NULL,
                created_at TEXT NOT NULL,
                last_active_at TEXT NOT NULL,
                attributes TEXT NOT NULL
            )
            SQL);
    }

    private static function createRememberMeSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE remember_me_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                previous_session_id TEXT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            SQL);
    }

    private static function createOneTimeTokenSchema(DatabaseInterface $database): void
    {
        $database->execute(<<<'SQL'
            CREATE TABLE one_time_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT NULL,
                created_at TEXT NOT NULL
            )
            SQL);
    }

    private static function createRefreshSchema(DatabaseInterface $database): void
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
                challenge_id TEXT NOT NULL UNIQUE,
                verifier TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL
            )
            SQL);
    }
}
