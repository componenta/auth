<?php

declare(strict_types=1);

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\CriticalEventListenerInterface;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
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

final readonly class TerminateAllGateListener implements CriticalEventListenerInterface
{
    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events;

    /** @param class-string<EventInterface> $eventClass */
    public function __construct(
        string $eventClass,
        private string $readyPath,
        private string $releasePath,
    ) {
        $this->events = [$eventClass];
    }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void {
        file_put_contents($this->readyPath, '1');
        $deadline = microtime(true) + 10.0;

        while (!is_file($this->releasePath)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Pre-commit concurrency gate timed out.');
            }

            usleep(1000);
        }
    }
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

function terminateAllWaitForFile(
    string $path,
    string $label,
    ?string $workerResultPath = null,
): void {
    $deadline = microtime(true) + 10.0;

    while (!is_file($path)) {
        if ($workerResultPath !== null && is_file($workerResultPath)) {
            $payload = json_decode(
                (string) file_get_contents($workerResultPath),
                true,
                512,
                JSON_THROW_ON_ERROR,
            );
            $detail = is_array($payload)
                ? (($payload['ok'] ?? false) === true
                    ? 'worker completed before the expected gate: '
                        . (string) ($payload['value'] ?? '')
                    : 'worker failed before the expected gate: '
                        . (string) ($payload['error'] ?? 'unknown'))
                : 'worker produced an unreadable result before the expected gate';

            throw new RuntimeException($label . ': ' . $detail);
        }

        if (microtime(true) >= $deadline) {
            throw new RuntimeException($label . ' timed out.');
        }

        usleep(1000);
    }
}

function terminateAllWaitForLockWait(): void
{
    $dsn = getenv('AUTH_TEST_MYSQL_DSN');
    $user = getenv('AUTH_TEST_MYSQL_USER');
    $password = getenv('AUTH_TEST_MYSQL_PASSWORD');

    if (!is_string($dsn) || $dsn === '') {
        throw new RuntimeException('AUTH_TEST_MYSQL_DSN is missing.');
    }

    $pdo = new PDO(
        $dsn,
        is_string($user) ? $user : '',
        is_string($password) ? $password : '',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
    );
    $deadline = microtime(true) + 10.0;

    do {
        $count = $pdo->query(
            'SELECT COUNT(*) FROM performance_schema.data_lock_waits',
        )->fetchColumn();

        if ((int) $count > 0) {
            return;
        }

        usleep(5000);
    } while (microtime(true) < $deadline);

    throw new RuntimeException(
        'The second session transition did not reach a real InnoDB lock wait.',
    );
}

/** @param Closure(): string $worker */
function terminateAllFork(string $resultPath, Closure $worker): int
{
    $pid = pcntl_fork();

    if ($pid === -1) {
        throw new RuntimeException('Unable to fork terminate-all concurrency worker.');
    }

    if ($pid === 0) {
        try {
            $value = $worker();
            file_put_contents($resultPath, json_encode([
                'ok' => true,
                'value' => $value,
            ], JSON_THROW_ON_ERROR));
            exit(0);
        } catch (Throwable $exception) {
            file_put_contents($resultPath, json_encode([
                'ok' => false,
                'error' => $exception::class . ': ' . $exception->getMessage(),
            ], JSON_THROW_ON_ERROR));
            exit(2);
        }
    }

    return $pid;
}

/** @param list<int> $pids @return list<string> */
function terminateAllCollect(array $pids, string $dir): array
{
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
}

function terminateAllDb(): DatabaseInterface
{
    return MySqlDatabaseFixture::create();
}

function terminateAllSubjectId(): UuidInterface
{
    return Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
}

function terminateAllManager(
    DatabaseInterface $database,
    ?CriticalEventListenerInterface $listener = null,
): DatabaseSessionManager {
    $provider = new PriorityListenerProvider();

    if ($listener !== null) {
        $provider->addListener($listener);
    }

    return new DatabaseSessionManager(
        $database,
        new SessionIdGenerator(),
        new FrozenClock(1000, 'UTC'),
        new EventDispatcher($provider),
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

/** @param list<int> $pids */
function terminateAllCleanupRaceDir(string $dir, array $pids, string $releasePath): void
{
    @file_put_contents($releasePath, '1');

    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }

    foreach (glob($dir . '/*') ?: [] as $path) {
        @unlink($path);
    }

    @rmdir($dir);
}

function verifySessionTerminateAllOrdering(bool $regenerationFirst): void
{
    $label = $regenerationFirst ? 'regeneration-first' : 'termination-first';
    $database = terminateAllDb();
    resetTerminateAllSchema($database);
    $old = terminateAllManager($database)->create(terminateAllSubjectId(), [
        DatabaseSessionManager::ATTR_IP => '127.0.0.1',
        DatabaseSessionManager::ATTR_USER_AGENT => 'mysql-terminate-all-race-test',
    ]);
    $dir = sys_get_temp_dir()
        . '/componenta-auth-terminate-all-race-'
        . bin2hex(random_bytes(8));

    if (!mkdir($dir, 0700) && !is_dir($dir)) {
        throw new RuntimeException('Unable to create terminate-all race directory.');
    }

    $readyPath = $dir . '/first-precommit';
    $releasePath = $dir . '/release-first';
    $secondStartedPath = $dir . '/second-started';
    $result0Path = $dir . '/result-0';
    $result1Path = $dir . '/result-1';
    $pids = [];

    try {
        $eventClass = $regenerationFirst
            ? SessionRegenerated::class
            : AllSessionsTerminated::class;
        $pids[] = terminateAllFork(
            $result0Path,
            static function () use (
                $old,
                $eventClass,
                $readyPath,
                $releasePath,
                $regenerationFirst,
            ): string {
                $gate = new TerminateAllGateListener(
                    $eventClass,
                    $readyPath,
                    $releasePath,
                );
                $manager = terminateAllManager(terminateAllDb(), $gate);

                if ($regenerationFirst) {
                    $manager->regenerate($old->id);

                    return 'regenerated';
                }

                $manager->terminateAll(terminateAllSubjectId());

                return 'terminated-all';
            },
        );

        terminateAllWaitForFile(
            $readyPath,
            'First ' . $label . ' transition did not reach its pre-commit gate',
            $result0Path,
        );

        $pids[] = terminateAllFork(
            $result1Path,
            static function () use (
                $old,
                $secondStartedPath,
                $regenerationFirst,
            ): string {
                file_put_contents($secondStartedPath, '1');
                $manager = terminateAllManager(terminateAllDb());

                if ($regenerationFirst) {
                    $manager->terminateAll(terminateAllSubjectId());

                    return 'terminated-all';
                }

                try {
                    $manager->regenerate($old->id);

                    return 'regenerated';
                } catch (ConcurrentRegenerationException|InvalidArgumentException) {
                    return 'regeneration-lost';
                }
            },
        );

        terminateAllWaitForFile(
            $secondStartedPath,
            'Second ' . $label . ' transition did not start',
            $result1Path,
        );
        terminateAllWaitForLockWait();
        file_put_contents($releasePath, '1');
        $results = terminateAllCollect($pids, $dir);

        terminateAllInvariant(
            $results[0] === ($regenerationFirst ? 'regenerated' : 'terminated-all'),
            'First directed session transition produced an unexpected outcome',
            [$label, $results],
        );
        terminateAllInvariant(
            $results[1] === ($regenerationFirst ? 'terminated-all' : 'regeneration-lost'),
            'Second directed session transition produced an unexpected outcome',
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
            [$label, $results, $remaining],
        );
    } finally {
        terminateAllCleanupRaceDir($dir, $pids, $releasePath);
    }
}

try {
    verifySessionTerminateAllOrdering(true);
    verifySessionTerminateAllOrdering(false);
    fwrite(STDOUT, "MySQL terminate-all concurrency invariant: OK\n");
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class . ': ' . $exception->getMessage() . "\n");
    exit(1);
}
