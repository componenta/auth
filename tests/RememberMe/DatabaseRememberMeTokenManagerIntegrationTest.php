<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\RememberMe;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseRememberMeTokenManagerIntegrationTest extends TestCase
{
    public function testBearerRotationIsSingleWinnerAndDoesNotDeleteGrantRow(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $plainToken = $manager->create(self::subjectId(), 'old-session');

        $rotation = $manager->rotate($plainToken);

        self::assertNotNull($rotation);
        self::assertSame('old-session', $rotation->previousSessionId);
        self::assertNull($manager->rotate($plainToken));
        self::assertSame(1, $database->select()->from('remember_me_tokens')->count());
    }

    public function testLogoutAfterBearerRotationPreventsBindingSuccessorSession(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $plainToken = $manager->create(self::subjectId(), 'old-session');
        $rotation = $manager->rotate($plainToken);
        self::assertNotNull($rotation);

        $manager->revokeForSession('old-session');

        self::assertFalse($manager->bindRotation($rotation, 'new-session'));
        self::assertNull($manager->rotate($rotation->successorToken));
    }

    public function testLogoutOfPreviousSessionRevokesAlreadyBoundSuccessorGrant(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $plainToken = $manager->create(self::subjectId(), 'old-session');
        $rotation = $manager->rotate($plainToken);
        self::assertNotNull($rotation);
        self::assertTrue($manager->bindRotation($rotation, 'new-session'));

        $manager->revokeForSession('old-session');

        self::assertNull($manager->rotate($rotation->successorToken));
    }

    public function testBatchRevokePreservesNumericStringSessionId(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $manager->create(self::subjectId(), '1');

        $manager->revokeForSessions(['1', '1']);

        self::assertSame(0, $database->select()->from('remember_me_tokens')->count());
    }

    public function testRevokeAllExceptKeepsOnlyTheSelectedCurrentSession(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $subjectId = self::subjectId();
        $manager->create($subjectId, 'keep-session');
        $manager->create($subjectId, 'other-session');

        $manager->revokeAllForSubject($subjectId, 'keep-session');

        $rows = $database
            ->select('session_id')
            ->from('remember_me_tokens')
            ->run()
            ->fetchAll();

        self::assertSame([['session_id' => 'keep-session']], $rows);
    }

    private static function manager(DatabaseInterface $database): DatabaseRememberMeTokenManager
    {
        return new DatabaseRememberMeTokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
            new DatabaseRememberMeTokenManagerConfig(),
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required for storage integration tests.');
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
}
