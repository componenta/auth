<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Otp;

use Componenta\Auth\Http\Strategy\Otp\CodeVerificationStatus;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseCodeStoreIntegrationTest extends TestCase
{
    private const string DESTINATION = 'mail@example.com';
    private const string HMAC_KEY =
        'componenta-auth-otp-test-key-32-bytes-minimum';

    public function testAttemptsAreAtomicAndChallengeIsSingleWinner(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseCodeStore($database, self::HMAC_KEY);
        $subjectId = self::subjectId();

        $store->store(new StoredCode(
            $subjectId,
            '123456',
            self::DESTINATION,
            2000,
        ));

        $row = $database
            ->select('verifier')
            ->from('otp_codes')
            ->run()
            ->fetch();

        self::assertIsArray($row);
        self::assertIsString($row['verifier'] ?? null);
        self::assertNotSame('123456', $row['verifier']);

        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                self::DESTINATION,
                '000000',
                1000,
                3,
            )->status,
        );
        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                self::DESTINATION,
                '000001',
                1001,
                3,
            )->status,
        );
        self::assertSame(
            CodeVerificationStatus::TooManyAttempts,
            $store->verifyAndConsume(
                self::DESTINATION,
                '000002',
                1002,
                3,
            )->status,
        );
        self::assertSame(
            CodeVerificationStatus::TooManyAttempts,
            $store->verifyAndConsume(
                self::DESTINATION,
                '123456',
                1003,
                3,
            )->status,
        );

        $store->store(new StoredCode(
            $subjectId,
            '654321',
            self::DESTINATION,
            3000,
        ));

        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                self::DESTINATION,
                '123456',
                1004,
                3,
            )->status,
        );

        $verified = $store->verifyAndConsume(
            self::DESTINATION,
            '654321',
            1005,
            3,
        );

        self::assertSame(CodeVerificationStatus::Verified, $verified->status);
        self::assertNotNull($verified->subjectId);
        self::assertTrue($subjectId->equals($verified->subjectId));

        self::assertSame(
            CodeVerificationStatus::Invalid,
            $store->verifyAndConsume(
                self::DESTINATION,
                '654321',
                1006,
                3,
            )->status,
        );
    }

    public function testExpiredChallengeIsRemovedBeforeReplacement(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseCodeStore($database, self::HMAC_KEY);

        $store->store(new StoredCode(
            self::subjectId(),
            '123456',
            self::DESTINATION,
            1000,
        ));

        self::assertSame(
            CodeVerificationStatus::Expired,
            $store->verifyAndConsume(
                self::DESTINATION,
                '123456',
                1000,
                5,
            )->status,
        );
        self::assertSame(
            0,
            $database->select()->from('otp_codes')->count(),
        );

        $store->store(new StoredCode(
            self::subjectId(),
            '654321',
            self::DESTINATION,
            2000,
        ));

        self::assertSame(
            CodeVerificationStatus::Verified,
            $store->verifyAndConsume(
                self::DESTINATION,
                '654321',
                1001,
                5,
            )->status,
        );
    }

    public function testCleanupIsBoundedAndRechecksExpiryBeforeDelete(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseCodeStore($database, self::HMAC_KEY);

        $store->store(new StoredCode(
            self::subjectId(),
            '111111',
            'expired-a@example.com',
            900,
        ));
        $store->store(new StoredCode(
            self::subjectId(),
            '222222',
            'expired-b@example.com',
            950,
        ));
        $store->store(new StoredCode(
            self::subjectId(),
            '333333',
            'active@example.com',
            2000,
        ));

        self::assertSame(1, $store->cleanup(1000, 1));
        self::assertSame(2, $database->select()->from('otp_codes')->count());
        self::assertSame(1, $store->cleanup(1000, 10));
        self::assertSame(1, $database->select()->from('otp_codes')->count());
        self::assertSame(0, $store->cleanup(1000, 10));
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

    private static function createSchema(DatabaseInterface $database): void
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
        $database->execute(
            'CREATE INDEX idx_otp_expiry ON otp_codes(expires_at)',
        );
    }
}
