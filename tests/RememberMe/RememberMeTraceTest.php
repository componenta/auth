<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\RememberMe;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class RememberMeTraceTest extends TestCase
{
    public function testRejectedSessionIdDoesNotAppearInTrace(): void
    {
        $previous = ini_get('zend.exception_ignore_args');
        self::assertIsString($previous);
        self::assertNotFalse(ini_set('zend.exception_ignore_args', '0'));

        try {
            $manager = new DatabaseRememberMeTokenManager(
                $this->createStub(DatabaseInterface::class),
                new FrozenClock(1000, 'UTC'),
            );
            $sessionId = "session-secret\n";

            try {
                $manager->create(
                    Uuid::fromString(
                        '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
                    ),
                    $sessionId,
                );
                self::fail('Invalid session ID must be rejected.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringNotContainsString(
                    'session-secret',
                    var_export($exception->getTrace(), true),
                );
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function testMalformedStoredGrantDoesNotExposeSessionIdInTrace(): void
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
            $plainToken = str_repeat('a', 64);
            $database->insert('remember_me_tokens')->values([
                'user_id' => 'not-a-uuid',
                'token' => hash('sha256', $plainToken),
                'session_id' => 'session-secret',
                'previous_session_id' => null,
                'expires_at' => '1970-01-01 01:00:00',
                'created_at' => '1970-01-01 00:00:00',
            ])->run();
            $manager = new DatabaseRememberMeTokenManager(
                $database,
                new FrozenClock(1000, 'UTC'),
            );

            try {
                $manager->rotate($plainToken);
            } catch (\Throwable $exception) {
                $trace = var_export($exception->getTrace(), true);
                self::assertStringNotContainsString('session-secret', $trace);
                self::assertStringNotContainsString($plainToken, $trace);

                return;
            }

            self::fail('Corrupted subject UUID must fail grant hydration.');
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
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
