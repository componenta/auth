<?php

declare(strict_types=1);

namespace Componenta\Auth\IntegrationTests;

use Componenta\Auth\Session\Database\Tests\Support\MySqlDatabaseFixture;
use Componenta\Auth\Session\Database\Tests\Support\PostgresDatabaseFixture;
use Cycle\Database\DatabaseInterface;

require_once dirname(__DIR__, 2) . '/auth-session-database/tests/Support/MySqlDatabaseFixture.php';
require_once dirname(__DIR__, 2) . '/auth-session-database/tests/Support/PostgresDatabaseFixture.php';

function databaseAvailable(string $engine): bool
{
    return $engine === 'mysql' ? MySqlDatabaseFixture::available() : PostgresDatabaseFixture::available();
}

function database(string $engine): DatabaseInterface
{
    $db = $engine === 'mysql' ? MySqlDatabaseFixture::create() : PostgresDatabaseFixture::create();
    if ($engine === 'mysql') {
        $db->execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        $db->execute('SET SESSION innodb_lock_wait_timeout = 15');
    } else {
        $db->execute("SET lock_timeout = '15s'");
    }
    return $db->withPrefix('race_');
}

/** Separate process/connection; no inherited PDO sockets or timing-based success claims. */
final class Worker
{
    private mixed $process = null;
    private array $pipes = [];
    private string $buffer = '';
    public int $backendId;

    public function __construct(array $input)
    {
        $this->process = proc_open([PHP_BINARY, __DIR__ . '/storage-worker.php'], [
            0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $this->pipes);
        if (!is_resource($this->process)) {
            throw new \RuntimeException('Cannot start isolated storage worker.');
        }
        stream_set_blocking($this->pipes[1], false);
        stream_set_blocking($this->pipes[2], false);
        fwrite($this->pipes[0], json_encode($input, JSON_THROW_ON_ERROR) . "\n");
        try {
            $event = $this->awaitEvent();
            if (($event['event'] ?? null) !== 'ready') {
                throw new \RuntimeException('Storage worker was not ready: ' . json_encode($event));
            }
            $this->backendId = $event['backendId'];
        } catch (\Throwable $error) {
            $this->close();
            throw $error;
        }
    }

    public function poll(): ?array
    {
        $this->buffer .= stream_get_contents($this->pipes[1]);
        $position = strpos($this->buffer, "\n");
        if ($position === false) {
            return null;
        }
        $line = substr($this->buffer, 0, $position);
        $this->buffer = substr($this->buffer, $position + 1);
        return json_decode($line, true, 32, JSON_THROW_ON_ERROR);
    }

    public function awaitEvent(): array
    {
        $deadline = microtime(true) + 20;
        do {
            if (($event = $this->poll()) !== null) {
                return $event;
            }
            $status = proc_get_status($this->process);
            if (!$status['running']) {
                throw new \RuntimeException('Storage worker exited: ' . stream_get_contents($this->pipes[2]));
            }
            usleep(10_000);
        } while (microtime(true) < $deadline);
        throw new \RuntimeException('Storage worker barrier timed out.');
    }

    public function release(): void
    {
        fwrite($this->pipes[0], "release\n");
        fflush($this->pipes[0]);
    }

    /** Wait for a real database lock, or a completed concurrent operation. */
    public function blockedOrFinished(DatabaseInterface $db, string $engine): ?array
    {
        $deadline = microtime(true) + 10;
        do {
            if (($event = $this->poll()) !== null) {
                return $event;
            }
            $sql = $engine === 'mysql'
                ? 'SELECT 1 FROM performance_schema.data_lock_waits w JOIN performance_schema.threads t ON t.THREAD_ID = w.REQUESTING_THREAD_ID WHERE t.PROCESSLIST_ID = ?'
                : "SELECT 1 FROM pg_stat_activity WHERE pid = ? AND wait_event_type = 'Lock'";
            if ($db->query($sql, [$this->backendId])->fetch() !== false) {
                return null;
            }
            usleep(20_000);
        } while (microtime(true) < $deadline);
        throw new \RuntimeException('No observable lock wait or completion from contender.');
    }

    public function close(): void
    {
        if (!is_resource($this->process)) {
            return;
        }
        foreach ($this->pipes as $pipe) {
            fclose($pipe);
        }
        if (proc_get_status($this->process)['running']) {
            proc_terminate($this->process);
        }
        proc_close($this->process);
        $this->process = null;
    }

    public function __destruct() { $this->close(); }
}
