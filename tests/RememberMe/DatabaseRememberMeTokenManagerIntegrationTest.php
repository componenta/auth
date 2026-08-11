<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\RememberMe;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class DatabaseRememberMeTokenManagerIntegrationTest extends TestCase
{
    public function testRevokeAllExceptKeepsOnlyTheSelectedSessionIncludingNullableRows(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite is required for storage integration tests.');
        }

        $database = SqliteDatabaseFixture::create();
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
        $manager = new DatabaseRememberMeTokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
            new DatabaseRememberMeTokenManagerConfig(),
        );
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $manager->create($subjectId, 'keep-session');
        $manager->create($subjectId, 'other-session');
        $manager->create($subjectId, null);

        $manager->revokeAllForSubject($subjectId, 'keep-session');

        $rows = $database
            ->select('session_id')
            ->from('remember_me_tokens')
            ->run()
            ->fetchAll();

        self::assertSame([['session_id' => 'keep-session']], $rows);
    }
}
