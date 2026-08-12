<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Token;

use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Token\TokenConfig;
use Componenta\Auth\Token\TokenManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class TokenManagerIntegrationTest extends TestCase
{
    public function testReplacementUsesOneCanonicalRowAndInvalidatesTheOldToken(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
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
        $manager = new TokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
            new TokenConfig('one_time_tokens', 'magic_link'),
        );
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );

        $old = $manager->replaceForSubject($subjectId);
        $current = $manager->replaceForSubject($subjectId);

        self::assertSame(
            1,
            $database->select()->from('one_time_tokens')->count(),
        );
        self::assertFalse($manager->consume($old));
        self::assertTrue($manager->consume($current));
        self::assertFalse($manager->consume($current));
    }

    public function testPurposeDomainSeparationRejectsTokenInAnotherFlow(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
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
        $clock = new FrozenClock(1000, 'UTC');
        $magicLink = new TokenManager(
            $database,
            $clock,
            new TokenConfig('one_time_tokens', 'magic_link'),
        );
        $passwordReset = new TokenManager(
            $database,
            $clock,
            new TokenConfig('one_time_tokens', 'password_reset'),
        );
        $token = $magicLink->replaceForSubject(Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        ));

        self::assertNotNull($magicLink->find($token));
        self::assertNull($passwordReset->find($token));
        self::assertFalse($passwordReset->consume($token));
    }
}
