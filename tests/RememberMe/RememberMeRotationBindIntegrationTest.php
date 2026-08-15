<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\RememberMe;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class RememberMeRotationBindIntegrationTest extends TestCase
{
    public function testBindAcceptsSessionAlreadyReboundByCriticalRegenerationListener(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = new DatabaseRememberMeTokenManager(
            $database,
            new FrozenClock(1000, 'UTC'),
        );
        $plainToken = $manager->create(self::subjectId(), 'old-session');
        $rotation = $manager->rotate($plainToken);
        self::assertInstanceOf(RememberMeRotation::class, $rotation);

        // This is the state a critical SessionRegenerated listener can commit
        // while RememberMeStrategy is still completing the same rotation.
        $manager->updateSessionId('old-session', 'new-session');

        $rebound = $database
            ->select(['session_id', 'previous_session_id'])
            ->from('remember_me_tokens')
            ->run()
            ->fetch();
        self::assertIsArray($rebound);
        self::assertSame('new-session', $rebound['session_id'] ?? null);
        self::assertSame('old-session', $rebound['previous_session_id'] ?? null);

        self::assertTrue($manager->bindRotation($rotation, 'new-session'));
        $nextRotation = $manager->rotate($rotation->successorToken);
        self::assertInstanceOf(RememberMeRotation::class, $nextRotation);
        self::assertSame('new-session', $nextRotation->previousSessionId);
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
                verifier TEXT NOT NULL,
                session_id TEXT NOT NULL,
                previous_session_id TEXT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            SQL);
    }
}
