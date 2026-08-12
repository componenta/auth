<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class SessionRegenerationSecurityTest extends TestCase
{
    public function testReplacedCredentialCannotResolveToItsSuccessor(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $old = $manager->create(self::subjectId(), self::attributes());
        $new = $manager->regenerate($old->id);

        self::assertFalse($manager->exists($old->id));
        self::assertNull($manager->find($old->id));
        self::assertTrue($manager->exists($new->id));
        self::assertSame($new->id, $manager->find($new->id)?->id);
    }

    public function testTerminationOfPresentedCredentialTerminatesItsRegeneratedSuccessor(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $old = $manager->create(self::subjectId(), self::attributes());
        $new = $manager->regenerate($old->id);

        // Models logout holding the previously authenticated session while a
        // concurrent request has already committed regeneration.
        $manager->terminate($old->id);

        self::assertFalse($manager->exists($old->id));
        self::assertFalse($manager->exists($new->id));
        self::assertSame(0, $database->select()->from('sessions')->count());
    }

    public function testCleanupPreservesReplacementLineageUntilAbsoluteExpiry(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database, 1000);
        $old = $manager->create(self::subjectId(), self::attributes());
        $new = $manager->regenerate($old->id);

        // The old row's regeneration grace period has elapsed, but its
        // replacement remains active and logout may still hold the old ID.
        $afterGrace = self::manager($database, 1040);

        self::assertSame(0, $afterGrace->cleanup());
        self::assertSame(2, $database->select()->from('sessions')->count());
        self::assertTrue($afterGrace->exists($new->id));

        $afterGrace->terminate($old->id);

        self::assertFalse($afterGrace->exists($new->id));
        self::assertSame(0, $database->select()->from('sessions')->count());
    }

    public function testRepeatedRegenerationNeverDisclosesWinningSuccessor(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager($database);
        $old = $manager->create(self::subjectId(), self::attributes());
        $manager->regenerate($old->id);

        $this->expectException(ConcurrentRegenerationException::class);

        $manager->regenerate($old->id);
    }

    private static function manager(
        DatabaseInterface $database,
        int $timestamp = 1000,
    ): DatabaseSessionManager {
        return new DatabaseSessionManager(
            $database,
            new SessionIdGenerator(),
            new FrozenClock($timestamp, 'UTC'),
            new EventDispatcher(new PriorityListenerProvider()),
            new DatabaseSessionManagerConfig(),
        );
    }

    private static function subjectId(): \Componenta\Identity\UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }

    /** @return array{ip: string, user_agent: string} */
    private static function attributes(): array
    {
        return [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'regeneration-security-test',
        ];
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped(
                'pdo_sqlite is required for storage integration tests.',
            );
        }
    }

    private static function createSchema(DatabaseInterface $database): void
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
}
