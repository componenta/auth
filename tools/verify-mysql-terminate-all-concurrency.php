<?php

declare(strict_types=1);

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;

require dirname(__DIR__) . '/vendor/autoload.php';

if (!extension_loaded('pcntl')) {
    fwrite(STDERR, "pcntl is required for the MySQL terminate-all concurrency gate.\n");
    exit(1);
}

if (!MySqlDatabaseFixture::available()) {
    fwrite(STDERR, "AUTH_TEST_MYSQL_DSN and pdo_mysql are required.\n");
    exit(1);
}

function terminateAllInvariant(bool $condition, string $message, mixed $actual = null): void
{
    if ($condition) {
        return;
    }

    if ($actual !== null) {
        $message .= ': ' . var_export($actual, true);
    }

    throw new RuntimeException($message);
}

/**
 * @param list<Closure(): string> $workers
 * @return list<string>
 */
function terminateAllRace(array $workers): array
{
    $dir = sys_get_temp_dir()
        . '/componenta-auth-terminate-all-race-'
        . bin2hex(random_bytes(8));

    if (!mkdir($dir, 0700) && !is_dir($dir)) {
        throw new RuntimeException('Unable to create terminate-all race barrier directory.');
    }

    $pids = [];

    try {
        foreach ($workers as $index => $worker) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Unable to fork terminate-all concurrency worker.');
            }

            if ($pid === 0) {
                file_put_contents($dir . '/ready-' . $index, '1');
                $deadline = microtime(true) + 10.0;

                while (!is_file($dir . '/go')) {
                    if (microtime(true) >= $deadline) {
                        file_put_contents($dir . '/result-' . $index, json_encode([
                            'ok' => false,
                            'error' => 'barrier timeout',
                        ], JSON_THROW_ON_ERROR));
                        exit(2);
                    }

                    usleep(1000);
                }

                try {
                    $value = $worker();
                    file_put_contents($dir . '/result-' . $index, json_encode([
                        'ok' => true,
                        'value' => $value,
                    ], JSON_THROW_ON_ERROR));
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($dir . '/result-' . $index, json_encode([
                        'ok' => false,
                        'error' => $exception::class . ': ' . $exception->getMessage(),
                    ], JSON_THROW_ON_ERROR));
                    exit(3);
                }
            }

            $pids[] = $pid;
        }

        $deadline = microtime(true) + 10.0;

        while (count(glob($dir . '/ready-*') ?: []) !== count($workers)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Terminate-all concurrency workers did not reach the barrier.');
            }

            usleep(1000);
        }

        file_put_contents($dir . '/go', '1');
        $values = [];

        foreach ($pids as $index => $pid) {
            pcntl_waitpid($pid, $status);
            $path = $dir . '/result-' . $index;
            $payload = is_file($path)
                ? json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR)
                : null;

            if (!is_array($payload) || ($payload['ok'] ?? false) !== true) {
                throw new RuntimeException(
                    'Terminate-all concurrency worker failed: '
                    . (is_array($payload)
                        ? (string) ($payload['error'] ?? 'unknown')
                        : 'missing result'),
                );
            }

            $values[] = (string) ($payload['value'] ?? '');
        }

        return $values;
    } finally {
        foreach (glob($dir . '/*') ?: [] as $path) {
            @unlink($path);
        }

        @rmdir($dir);
    }
}

function terminateAllDb(): DatabaseInterface
{
    return MySqlDatabaseFixture::create();
}

function terminateAllSubjectId(): Componenta\Identity\UuidInterface
{
    return Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
}

function terminateAllManager(DatabaseInterface $database): DatabaseSessionManager
{
    return new DatabaseSessionManager(
        $database,
        new SessionIdGenerator(),
        new FrozenClock(1000, 'UTC'),
        new EventDispatcher(new PriorityListenerProvider()),
        new DatabaseSessionManagerConfig(),
    );
}

function resetTerminateAllSchema(DatabaseInterface $database): void
{
    $database->execute('DROP TABLE IF EXISTS sessions');
    $database->execute(<<<'SQL'
        CREATE TABLE sessions (
            id VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
            user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            ip VARCHAR(45) NOT NULL,
            user_agent VARCHAR(1024) NOT NULL,
            expires_at DATETIME NOT NULL,
            absolute_expires_at DATETIME NOT NULL,
            regenerate_at DATETIME NOT NULL,
            replaced_by VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
            created_at DATETIME NOT NULL,
            last_active_at DATETIME NOT NULL,
            attributes TEXT NOT NULL,
            INDEX idx_session_subject (user_id),
            INDEX idx_session_replaced (replaced_by),
            INDEX idx_session_cleanup_idle (replaced_by, expires_at),
            INDEX idx_session_cleanup_absolute (absolute_expires_at)
        ) ENGINE=InnoDB
        SQL);
}

function verifySessionTerminateAllRace(): void
{
    foreach ([
        'regeneration-first' => false,
        'termination-first' => true,
    ] as $label => $delayRegeneration) {
        for ($iteration = 0; $iteration < 4; ++$iteration) {
            $database = terminateAllDb();
            resetTerminateAllSchema($database);
            $old = terminateAllManager($database)->create(terminateAllSubjectId(), [
                DatabaseSessionManager::ATTR_IP => '127.0.0.1',
                DatabaseSessionManager::ATTR_USER_AGENT => 'mysql-terminate-all-race-test',
            ]);

            $results = terminateAllRace([
                static function () use ($old, $delayRegeneration): string {
                    if ($delayRegeneration) {
                        usleep(100000);
                    }

                    try {
                        terminateAllManager(terminateAllDb())->regenerate($old->id);

                        return 'regenerated';
                    } catch (ConcurrentRegenerationException|InvalidArgumentException) {
                        return 'regeneration-lost';
                    }
                },
                static function () use ($delayRegeneration): string {
                    if (!$delayRegeneration) {
                        usleep(100000);
                    }

                    terminateAllManager(terminateAllDb())->terminateAll(
                        terminateAllSubjectId(),
                    );

                    return 'terminated-all';
                },
            ]);

            terminateAllInvariant(
                in_array('terminated-all', $results, true),
                'Subject-wide session termination worker did not complete',
                [$label, $results],
            );
            terminateAllInvariant(
                in_array(
                    $delayRegeneration ? 'regeneration-lost' : 'regenerated',
                    $results,
                    true,
                ),
                'Directed terminate-all race did not exercise the intended ordering',
                [$label, $results],
            );

            $remaining = terminateAllDb()
                ->select()
                ->from('sessions')
                ->where('user_id', terminateAllSubjectId()->toString())
                ->count();

            terminateAllInvariant(
                $remaining === 0,
                'Concurrent terminateAll left an active session descendant',
                [$label, $iteration, $results, $remaining],
            );
        }
    }
}

try {
    verifySessionTerminateAllRace();
    fwrite(STDOUT, "MySQL terminate-all concurrency invariant: OK\n");
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class . ': ' . $exception->getMessage() . "\n");
    exit(1);
}
