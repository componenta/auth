<?php

declare(strict_types=1);

use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;

require dirname(__DIR__) . '/vendor/autoload.php';

if (!extension_loaded('pcntl')) {
    fwrite(STDERR, "pcntl is required for the MySQL concurrency gate.\n");
    exit(1);
}

if (!MySqlDatabaseFixture::available()) {
    fwrite(STDERR, "AUTH_TEST_MYSQL_DSN and pdo_mysql are required.\n");
    exit(1);
}

/** @param mixed $actual */
function invariant(bool $condition, string $message, mixed $actual = null): void
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
 * @param list<Closure(): mixed> $workers
 * @return list<mixed>
 */
function race(array $workers): array
{
    $dir = sys_get_temp_dir() . '/componenta-auth-race-' . bin2hex(random_bytes(8));
    if (!mkdir($dir, 0700) && !is_dir($dir)) {
        throw new RuntimeException('Unable to create race barrier directory.');
    }

    $pids = [];

    try {
        foreach ($workers as $index => $worker) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                throw new RuntimeException('Unable to fork concurrency worker.');
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
                throw new RuntimeException('Concurrency workers did not reach the barrier.');
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
                    'Concurrency worker failed: ' . (is_array($payload) ? (string) ($payload['error'] ?? 'unknown') : 'missing result'),
                );
            }

            $values[] = $payload['value'] ?? null;
        }

        return $values;
    } finally {
        foreach (glob($dir . '/*') ?: [] as $path) {
            @unlink($path);
        }
        @rmdir($dir);
    }
}

function db(): DatabaseInterface
{
    return MySqlDatabaseFixture::create();
}

function resetSchema(DatabaseInterface $database): void
{
    $database->execute('SET FOREIGN_KEY_CHECKS = 0');
    foreach ([
        'refresh_tokens',
        'refresh_token_families',
        'otp_codes',
        'remember_me_tokens',
    ] as $table) {
        $database->execute('DROP TABLE IF EXISTS ' . $table);
    }
    $database->execute('SET FOREIGN_KEY_CHECKS = 1');
}

function subjectId(): Componenta\Identity\UuidInterface
{
    return Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
}

function verifyRefreshRace(): void
{
    $database = db();
    resetSchema($database);
    $database->execute(<<<'SQL'
        CREATE TABLE refresh_token_families (
            family_id CHAR(64) NOT NULL PRIMARY KEY,
            user_id CHAR(36) NOT NULL,
            revoked_at BIGINT UNSIGNED NULL,
            compromised_at BIGINT UNSIGNED NULL,
            lock_nonce CHAR(32) NOT NULL,
            INDEX idx_refresh_family_subject (user_id)
        ) ENGINE=InnoDB
        SQL);
    $database->execute(<<<'SQL'
        CREATE TABLE refresh_tokens (
            token_hash CHAR(64) NOT NULL PRIMARY KEY,
            family_id CHAR(64) NOT NULL,
            user_id CHAR(36) NOT NULL,
            expires_at BIGINT UNSIGNED NOT NULL,
            consumed_at BIGINT UNSIGNED NULL,
            revoked_at BIGINT UNSIGNED NULL,
            INDEX idx_refresh_token_family (family_id),
            INDEX idx_refresh_token_subject (user_id),
            CONSTRAINT fk_refresh_family FOREIGN KEY (family_id)
                REFERENCES refresh_token_families(family_id)
        ) ENGINE=InnoDB
        SQL);

    $token = str_repeat('a', 64);
    $family = str_repeat('d', 64);
    (new DatabaseRefreshTokenStore($database))->storeInitial(
        new RefreshToken($token, subjectId(), $family, 5000),
    );

    $successors = [str_repeat('b', 64), str_repeat('c', 64)];
    $results = race([
        static fn(): string => (new DatabaseRefreshTokenStore(db()))
            ->rotateAtomically($token, $successors[0], 6000, 1000)
            ->status->value,
        static fn(): string => (new DatabaseRefreshTokenStore(db()))
            ->rotateAtomically($token, $successors[1], 6000, 1000)
            ->status->value,
    ]);
    sort($results);
    invariant($results === ['reused', 'rotated'], 'Concurrent refresh outcomes are invalid', $results);

    $verify = db();
    $active = $verify->select()->from('refresh_tokens')
        ->where('family_id', $family)
        ->where('revoked_at', null)
        ->count();
    invariant($active === 0, 'Refresh replay left an active descendant', $active);
    $familyRow = $verify->select('compromised_at')->from('refresh_token_families')
        ->where('family_id', $family)->run()->fetch();
    invariant(is_array($familyRow) && ($familyRow['compromised_at'] ?? null) !== null, 'Refresh family was not compromised');
}

function verifyOtpRace(): void
{
    $database = db();
    resetSchema($database);
    $database->execute(<<<'SQL'
        CREATE TABLE otp_codes (
            destination VARCHAR(320) NOT NULL PRIMARY KEY,
            user_id CHAR(36) NOT NULL,
            challenge_id CHAR(32) NOT NULL,
            verifier CHAR(64) NOT NULL,
            expires_at BIGINT UNSIGNED NOT NULL,
            attempts INT UNSIGNED NOT NULL
        ) ENGINE=InnoDB
        SQL);
    $key = 'componenta-auth-concurrency-otp-key-32-bytes-minimum';
    (new DatabaseCodeStore($database, $key))->store(new StoredCode(
        subjectId(),
        '123456',
        'race@example.com',
        5000,
    ));

    $results = race([
        static fn(): string => (new DatabaseCodeStore(db(), $key))
            ->verifyAndConsume('race@example.com', '123456', 1000, 5)
            ->status->value,
        static fn(): string => (new DatabaseCodeStore(db(), $key))
            ->verifyAndConsume('race@example.com', '123456', 1000, 5)
            ->status->value,
    ]);
    sort($results);
    invariant($results === ['invalid', 'verified'], 'OTP verification is not single-winner', $results);
    invariant(db()->select()->from('otp_codes')->count() === 0, 'Consumed OTP challenge remains active');
}

function verifyRememberLogoutRace(): void
{
    $database = db();
    resetSchema($database);
    $database->execute(<<<'SQL'
        CREATE TABLE remember_me_tokens (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id CHAR(36) NOT NULL,
            token CHAR(64) NOT NULL UNIQUE,
            session_id VARCHAR(512) NOT NULL,
            previous_session_id VARCHAR(512) NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            INDEX idx_remember_subject (user_id),
            INDEX idx_remember_session (session_id),
            INDEX idx_remember_previous_session (previous_session_id)
        ) ENGINE=InnoDB
        SQL);
    $clock = new FrozenClock(1000, 'UTC');
    $token = (new DatabaseRememberMeTokenManager($database, $clock))
        ->create(subjectId(), 'old-session');

    $results = race([
        static function () use ($token): string {
            $rotation = (new DatabaseRememberMeTokenManager(db(), new FrozenClock(1000, 'UTC')))
                ->rotate($token);
            return $rotation === null ? 'revoked-first' : 'rotated-first';
        },
        static function (): string {
            (new DatabaseRememberMeTokenManager(db(), new FrozenClock(1000, 'UTC')))
                ->revokeForSession('old-session');
            return 'revoked';
        },
    ]);

    invariant(in_array('revoked', $results, true), 'Remember-me revoke worker did not complete', $results);
    invariant(db()->select()->from('remember_me_tokens')->count() === 0, 'Concurrent logout left a remember-me descendant');
}

try {
    verifyRefreshRace();
    verifyOtpRace();
    verifyRememberLogoutRace();
    fwrite(STDOUT, "MySQL concurrency invariants: OK\n");
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class . ': ' . $exception->getMessage() . "\n");
    exit(1);
}
