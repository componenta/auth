<?php

declare(strict_types=1);

namespace Componenta\Auth\IntegrationTests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\RecoveryCode\DatabaseRecoveryCodeManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/storage-support.php';

function emit(array $message): void
{
    echo json_encode($message, JSON_THROW_ON_ERROR), "\n";
    flush();
}

try {
    $input = json_decode(trim(fgets(STDIN)), true, 32, JSON_THROW_ON_ERROR);
    $db = database($input['engine']);
    $pidRow = $db->query($input['engine'] === 'mysql'
        ? 'SELECT CONNECTION_ID() AS id' : 'SELECT pg_backend_pid() AS id')->fetch();
    emit(['event' => 'ready', 'backendId' => (int) $pidRow['id']]);
    $driver = $db->getDriver(DatabaseInterface::WRITE);
    if (!$driver instanceof LoggerAwareInterface) {
        throw new \RuntimeException('Test barrier requires a logger-aware Cycle driver.');
    }
    $driver->setLogger(new class($input['pause'] ?? '') extends AbstractLogger {
        private bool $paused = false;
        public function __construct(private string $mode) {}
        public function log($level, string|\Stringable $message, array $context = []): void
        {
            $sql = (string) $message;
            $match = $this->mode === 'recovery'
                ? str_starts_with($sql, 'DELETE') && str_contains($sql, 'race_auth_recovery_codes')
                : $this->mode === 'otp' && str_starts_with($sql, 'UPDATE')
                    && str_contains($sql, 'failure_budgets') && str_contains($sql, 'failures + 1');
            if (!$this->paused && $match) {
                $this->paused = true;
                emit(['event' => 'paused']);
                if (trim(fgets(STDIN)) !== 'release') {
                    throw new \RuntimeException('Storage test barrier not released.');
                }
            }
        }
    });
    $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
    if ($input['operation'] === 'recovery') {
        $batch = (new DatabaseRecoveryCodeManager($db, $clock))->regenerate(Uuid::fromString($input['subject']), 3);
        emit(['event' => 'done', 'count' => count($batch->codes)]);
    } else {
        $result = (new DatabaseOtpChallengeStore($db, $clock))->verify(
            Uuid::fromString($input['challenge']), $input['binding'], $input['verifier'],
            new OtpConfig(resendCooldownSeconds: 0, aggregateFailureLimit: 1),
        );
        emit(['event' => 'done', 'status' => $result->status->name]);
    }
} catch (\Throwable $error) {
    // Only synthetic test schema/values are involved; do not print bound parameters.
    emit(['event' => 'error', 'type' => $error::class, 'message' => $error->getMessage()]);
    exit(1);
}
