<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Jwt;

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseRefreshTokenStoreIntegrationTest extends TestCase
{
    private const string TOKEN_A =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const string TOKEN_B =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const string SUCCESSOR =
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
    private const string RETRY_SUCCESSOR =
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
    private const string FAMILY_A =
        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    private const string FAMILY_B =
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    public function testActiveSubjectPreflightReadsOnlyActiveGrantState(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = self::subjectId();
        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            $subjectId,
            self::FAMILY_A,
            2000,
        ));

        $resolved = $store->findActiveSubject(self::TOKEN_A, 1000);
        self::assertNotNull($resolved);
        self::assertTrue($subjectId->equals($resolved));
        self::assertNull($store->findActiveSubject(self::TOKEN_A, 2000));

        $store->revoke(self::TOKEN_A, 1001);
        self::assertNull($store->findActiveSubject(self::TOKEN_A, 1002));
    }

    public function testReplayCompromisesFamilyAndRevokesSuccessor(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = self::subjectId();

        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            $subjectId,
            self::FAMILY_A,
            2000,
        ));

        $stored = $database
            ->select('token_hash')
            ->from('refresh_tokens')
            ->run()
            ->fetch();

        self::assertIsArray($stored);
        self::assertSame(hash('sha256', self::TOKEN_A), $stored['token_hash']);
        self::assertNotSame(self::TOKEN_A, $stored['token_hash']);

        $rotated = $store->rotateAtomically(
            self::TOKEN_A,
            self::SUCCESSOR,
            3000,
            1000,
        );

        self::assertSame(RefreshTokenRotationStatus::Rotated, $rotated->status);
        self::assertNotNull($rotated->token);
        self::assertSame(self::SUCCESSOR, $rotated->token->id);
        self::assertTrue($subjectId->equals($rotated->token->subjectId));
        self::assertSame(self::FAMILY_A, $rotated->token->familyId);

        $replay = $store->rotateAtomically(
            self::TOKEN_A,
            self::RETRY_SUCCESSOR,
            3000,
            1001,
        );

        self::assertSame(RefreshTokenRotationStatus::Reused, $replay->status);

        $family = $database
            ->select(['revoked_at', 'compromised_at'])
            ->from('refresh_token_families')
            ->where('family_id', self::FAMILY_A)
            ->run()
            ->fetch();
        self::assertIsArray($family);
        self::assertNull($family['revoked_at'] ?? null);
        self::assertSame(1001, $family['compromised_at'] ?? null);

        $successor = $database
            ->select('revoked_at')
            ->from('refresh_tokens')
            ->where('token_hash', hash('sha256', self::SUCCESSOR))
            ->run()
            ->fetch();

        self::assertIsArray($successor);
        self::assertSame(1001, $successor['revoked_at'] ?? null);

        $descendant = $store->rotateAtomically(
            self::SUCCESSOR,
            self::RETRY_SUCCESSOR,
            4000,
            1002,
        );

        self::assertSame(RefreshTokenRotationStatus::Reused, $descendant->status);
    }

    public function testFailedSuccessorInsertRollsBackPresentedTokenClaim(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = self::subjectId();

        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            $subjectId,
            self::FAMILY_A,
            2000,
        ));
        $store->storeInitial(new RefreshToken(
            self::TOKEN_B,
            $subjectId,
            self::FAMILY_B,
            2000,
        ));

        try {
            $store->rotateAtomically(
                self::TOKEN_A,
                self::TOKEN_B,
                3000,
                1000,
            );
            self::fail('Duplicate successor token must fail.');
        } catch (\Throwable) {
            // The important invariant is that the transaction rolls the
            // presented-token claim and family deadline back with the failed insert.
        }

        $family = $database
            ->select('expires_at')
            ->from('refresh_token_families')
            ->where('family_id', self::FAMILY_A)
            ->run()
            ->fetch();
        self::assertIsArray($family);
        self::assertSame(2000, $family['expires_at'] ?? null);

        $retry = $store->rotateAtomically(
            self::TOKEN_A,
            self::RETRY_SUCCESSOR,
            3000,
            1001,
        );

        self::assertSame(RefreshTokenRotationStatus::Rotated, $retry->status);
        self::assertSame(
            self::RETRY_SUCCESSOR,
            $retry->token?->id,
        );
    }

    public function testBulkRevocationDoesNotPretendTheFamilyWasCompromised(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);
        $subjectId = self::subjectId();

        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            $subjectId,
            self::FAMILY_A,
            2000,
        ));
        $store->storeInitial(new RefreshToken(
            self::TOKEN_B,
            $subjectId,
            self::FAMILY_B,
            2000,
        ));

        $store->revokeAllForSubject($subjectId, 1000);

        self::assertSame(
            RefreshTokenRotationStatus::Invalid,
            $store->rotateAtomically(
                self::TOKEN_A,
                self::SUCCESSOR,
                3000,
                1001,
            )->status,
        );
        self::assertSame(
            RefreshTokenRotationStatus::Invalid,
            $store->rotateAtomically(
                self::TOKEN_B,
                self::SUCCESSOR,
                3000,
                1001,
            )->status,
        );

        $families = $database
            ->select(['revoked_at', 'compromised_at'])
            ->from('refresh_token_families')
            ->orderBy('family_id')
            ->run()
            ->fetchAll();

        self::assertCount(2, $families);
        foreach ($families as $family) {
            self::assertIsArray($family);
            self::assertSame(1000, $family['revoked_at'] ?? null);
            self::assertNull($family['compromised_at'] ?? null);
        }
    }

    public function testManualRevocationIsInvalidButNotReplay(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $store = new DatabaseRefreshTokenStore($database);

        $store->storeInitial(new RefreshToken(
            self::TOKEN_A,
            self::subjectId(),
            self::FAMILY_A,
            2000,
        ));
        $store->revoke(self::TOKEN_A, 1000);

        self::assertSame(
            RefreshTokenRotationStatus::Invalid,
            $store->rotateAtomically(
                self::TOKEN_A,
                self::SUCCESSOR,
                3000,
                1001,
            )->status,
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

    private static function createSchema(DatabaseInterface $database): void
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
}
