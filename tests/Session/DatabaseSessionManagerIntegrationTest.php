<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseSessionManagerIntegrationTest extends TestCase
{
    public function testTouchIsThrottledAndCleanupIsBounded(): void
    {
        self::requireSqlite();

        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $clock = new FrozenClock(1000, 'UTC');
        $manager = self::manager(
            $database,
            $clock,
            new EventDispatcher(new PriorityListenerProvider()),
        );
        $session = $manager->create(
            self::subjectId(),
            self::attributes(),
        );
        $initial = self::lastActive($database, $session->id);

        $clock->advance('+30 seconds');
        $manager->touch($session->id, $session->lastActiveAt);
        self::assertSame($initial, self::lastActive($database, $session->id));

        $clock->advance('+31 seconds');
        $manager->touch($session->id, $session->lastActiveAt);
        self::assertNotSame($initial, self::lastActive($database, $session->id));

        foreach (['expired-a', 'expired-b', 'expired-c'] as $id) {
            $database->execute(
                'INSERT INTO sessions '
                . '(id, user_id, ip, user_agent, expires_at, absolute_expires_at, regenerate_at, replaced_by, created_at, last_active_at, attributes) '
                . 'VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)',
                [
                    $id,
                    self::subjectId()->toString(),
                    '127.0.0.1',
                    'integration-test',
                    '1970-01-01 00:00:01',
                    '1970-01-01 00:00:02',
                    '1970-01-01 00:00:01',
                    '1970-01-01 00:00:00',
                    '1970-01-01 00:00:00',
                    '{}',
                ],
            );
        }

        self::assertSame(2, $manager->cleanup(2));
        self::assertSame(
            1,
            $database->select()->from('sessions')
                ->where('id', 'LIKE', 'expired-%')
                ->count(),
        );
    }

    public function testCriticalTerminationFailureRollsBackDeletedSession(): void
    {
        self::requireSqlite();

        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager(
            $database,
            new FrozenClock(1000, 'UTC'),
            self::failingDispatcher(),
        );
        $session = $manager->create(self::subjectId(), self::attributes());

        try {
            $manager->terminate($session->id);
            self::fail('Critical listener failure was not surfaced.');
        } catch (\RuntimeException $exception) {
            self::assertSame('critical session lifecycle failure', $exception->getMessage());
        }

        self::assertNotNull($manager->find($session->id));
        self::assertSame(1, self::sessionCount($database));
    }

    public function testCriticalRegenerationFailureRollsBackBothSessionRows(): void
    {
        self::requireSqlite();

        $database = SqliteDatabaseFixture::create();
        self::createSchema($database);
        $manager = self::manager(
            $database,
            new FrozenClock(1000, 'UTC'),
            self::failingDispatcher(),
        );
        $session = $manager->create(self::subjectId(), self::attributes());

        try {
            $manager->regenerate($session->id);
            self::fail('Critical listener failure was not surfaced.');
        } catch (\RuntimeException $exception) {
            self::assertSame('critical session lifecycle failure', $exception->getMessage());
        }

        $current = $manager->find($session->id);
        self::assertNotNull($current);
        self::assertSame($session->id, $current->id);
        self::assertSame(1, self::sessionCount($database));
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped(
                'pdo_sqlite is required for storage integration tests.',
            );
        }
    }

    private static function manager(
        DatabaseInterface $database,
        FrozenClock $clock,
        EventDispatcher $dispatcher,
    ): DatabaseSessionManager {
        return new DatabaseSessionManager(
            $database,
            new SessionIdGenerator(),
            $clock,
            $dispatcher,
            new DatabaseSessionManagerConfig(touchInterval: 60),
        );
    }

    private static function failingDispatcher(): EventDispatcher
    {
        return new EventDispatcher(new CriticalSessionListenerProviderFixture());
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
            DatabaseSessionManager::ATTR_USER_AGENT => 'integration-test',
        ];
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

    private static function lastActive(
        DatabaseInterface $database,
        string $sessionId,
    ): string {
        $row = $database->select('last_active_at')
            ->from('sessions')
            ->where('id', $sessionId)
            ->run()
            ->fetch();

        self::assertIsArray($row);
        self::assertIsString($row['last_active_at'] ?? null);

        return $row['last_active_at'];
    }

    private static function sessionCount(DatabaseInterface $database): int
    {
        return $database->select()->from('sessions')->count();
    }
}

final readonly class CriticalSessionListenerProviderFixture implements EventListenerProviderInterface
{
    public function provideFor(EventInterface $event): iterable
    {
        yield new CriticalSessionListenerFixture();
    }
}

final readonly class CriticalSessionListenerFixture implements CriticalEventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    public function __construct()
    {
        $this->events = [SessionsTerminated::class, SessionRegenerated::class];
    }

    public function handleEvent(EventInterface $event): void
    {
        throw new \RuntimeException('critical session lifecycle failure');
    }
}
