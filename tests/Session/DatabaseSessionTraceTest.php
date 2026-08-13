<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseSessionTraceTest extends TestCase
{
    public function testMalformedStoredSessionDoesNotExposePresentedIdInTrace(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped(
                'pdo_sqlite is required for storage integration tests.',
            );
        }

        $previous = ini_get('zend.exception_ignore_args');
        self::assertIsString($previous);
        self::assertNotFalse(ini_set('zend.exception_ignore_args', '0'));

        try {
            $database = SqliteDatabaseFixture::create();
            self::createSchema($database);
            $database->execute(
                'INSERT INTO sessions '
                . '(id, user_id, ip, user_agent, expires_at, absolute_expires_at, regenerate_at, replaced_by, created_at, last_active_at, attributes) '
                . 'VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)',
                [
                    'session-secret',
                    'not-a-uuid',
                    '127.0.0.1',
                    'trace-test',
                    '1970-01-01 00:30:00',
                    '1970-01-01 01:00:00',
                    '1970-01-01 00:20:00',
                    '1970-01-01 00:10:00',
                    '1970-01-01 00:15:00',
                    '{}',
                ],
            );
            $manager = new DatabaseSessionManager(
                $database,
                new SessionIdGenerator(),
                new FrozenClock(1000, 'UTC'),
                new EventDispatcher(new PriorityListenerProvider()),
            );

            try {
                $manager->find('session-secret');
                self::fail('Corrupted subject UUID must fail hydration.');
            } catch (\Throwable $exception) {
                self::assertStringNotContainsString(
                    'session-secret',
                    var_export($exception->getTrace(), true),
                );
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
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
