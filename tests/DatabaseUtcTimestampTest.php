<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Token\TokenConfig;
use Componenta\Auth\Token\TokenManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseUtcTimestampTest extends TestCase
{
    public function testSessionTimestampsAreStoredInUtc(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSessionSchema($database);
        $manager = new DatabaseSessionManager(
            $database,
            new SessionIdGenerator(),
            new FrozenClock(1000, 'Europe/Copenhagen'),
            new EventDispatcher(new PriorityListenerProvider()),
        );

        $session = $manager->create(self::subjectId(), [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'utc-test',
        ]);
        $row = $database->select(['created_at', 'expires_at'])
            ->from('sessions')
            ->where('id', $session->id)
            ->run()
            ->fetch();

        self::assertIsArray($row);
        self::assertSame('1970-01-01 00:16:40', $row['created_at']);
        self::assertSame('1970-01-01 00:46:40', $row['expires_at']);
        self::assertSame('UTC', $session->createdAt->getTimezone()->getName());
    }

    public function testRememberMeTimestampsAreStoredAndHydratedInUtc(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createRememberMeSchema($database);
        $manager = new DatabaseRememberMeTokenManager(
            $database,
            new FrozenClock(1000, 'Europe/Copenhagen'),
        );

        $plainToken = $manager->create(self::subjectId(), 'session-id');
        $row = $database->select(['created_at', 'expires_at'])
            ->from('remember_me_tokens')
            ->run()
            ->fetch();
        $token = $manager->consume($plainToken);

        self::assertIsArray($row);
        self::assertSame('1970-01-01 00:16:40', $row['created_at']);
        self::assertSame('1970-01-31 00:16:40', $row['expires_at']);
        self::assertNotNull($token);
        self::assertSame('UTC', $token->createdAt->getTimezone()->getName());
    }

    public function testOneTimeTokenTimestampsAreStoredAndHydratedInUtc(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createOneTimeTokenSchema($database);
        $manager = new TokenManager(
            $database,
            new FrozenClock(1000, 'Europe/Copenhagen'),
            new TokenConfig('one_time_tokens'),
        );

        $plainToken = $manager->replaceForSubject(self::subjectId());
        $row = $database->select(['created_at', 'expires_at'])
            ->from('one_time_tokens')
            ->run()
            ->fetch();
        $token = $manager->find($plainToken);

        self::assertIsArray($row);
        self::assertSame('1970-01-01 00:16:40', $row['created_at']);
        self::assertSame('1970-01-01 00:21:40', $row['expires_at']);
        self::assertNotNull($token);
        self::assertSame('UTC', $token->createdAt->getTimezone()->getName());
    }

    private static function subjectId(): \Componenta\Identity\UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
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
                session_id TEXT NULL,
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
}
