<?php

declare(strict_types=1);

namespace Componenta\Auth\IntegrationTests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallenge;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\RecoveryCode\DatabaseRecoveryCodeManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/storage-support.php';

final class StorageConcurrencyTest extends TestCase
{
    public static function recoveries(): iterable
    {
        foreach (['mysql', 'pgsql'] as $engine) {
            yield $engine . '-initial' => [$engine, false];
            yield $engine . '-replacement' => [$engine, true];
        }
    }

    public static function engines(): iterable
    {
        yield 'mysql-repeatable-read' => ['mysql'];
        yield 'postgres-read-committed' => ['pgsql'];
    }

    #[DataProvider('recoveries')]
    public function testConcurrentRegenerationsLeaveOnlyOneBatch(string $engine, bool $existing): void
    {
        $db = $this->prepare($engine, 'auth-recovery-code', ['auth_recovery_codes', 'auth_recovery_code_subject_locks']);
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $subject = (new UuidFactory())->generate();
        $manager = new DatabaseRecoveryCodeManager($db, $clock);
        if ($existing) {
            $manager->regenerate($subject, 3);
        }
        $input = ['engine' => $engine, 'operation' => 'recovery', 'subject' => $subject->toString()];
        $a = $b = null;
        try {
            $a = new Worker($input + ['pause' => 'recovery']);
            self::assertSame('paused', $a->awaitEvent()['event']);
            $b = new Worker($input);
            $bResult = $b->blockedOrFinished($db, $engine);
            $a->release();
            $aResult = $a->awaitEvent();
            $bResult ??= $b->awaitEvent();
            self::assertSame('done', $aResult['event'], json_encode($aResult));
            self::assertSame('done', $bResult['event'], json_encode($bResult));
            self::assertSame(3, $manager->remaining($subject));
            $batches = $db->select('batch_id')->from('auth_recovery_codes')->where('subject_uuid', $subject->toString())->run()->fetchAll();
            self::assertCount(1, array_unique(array_column($batches, 'batch_id')));
        } finally {
            $a?->close();
            $b?->close();
        }
    }

    #[DataProvider('engines')]
    public function testWaitingOtpVerificationSeesCommittedFailureBudget(string $engine): void
    {
        $db = $this->prepare($engine, 'auth-otp', ['auth_otp_challenges', 'auth_otp_failure_budgets']);
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $store = new DatabaseOtpChallengeStore($db, $clock);
        $config = new OtpConfig(resendCooldownSeconds: 0, aggregateFailureLimit: 1);
        $ids = [$uuids->generate(), $uuids->generate()];
        foreach ($ids as $i => $id) {
            $store->issue(new OtpChallenge($id, $subject, new OtpPurpose('authentication'), new OtpChannel('email'), 'binding-' . $i, $clock->now(), $clock->now()->modify('+300 seconds')), str_repeat('a', 64), $config);
        }
        $a = $b = null;
        try {
            $a = new Worker(['engine' => $engine, 'operation' => 'otp', 'challenge' => $ids[0]->toString(), 'binding' => 'binding-0', 'verifier' => str_repeat('b', 64), 'pause' => 'otp']);
            self::assertSame('paused', $a->awaitEvent()['event']);
            $b = new Worker(['engine' => $engine, 'operation' => 'otp', 'challenge' => $ids[1]->toString(), 'binding' => 'binding-1', 'verifier' => str_repeat('a', 64)]);
            $bResult = $b->blockedOrFinished($db, $engine);
            self::assertNull($bResult, 'The contender must wait behind the failure-budget transaction.');
            $a->release();
            self::assertSame(['event' => 'done', 'status' => 'RateLimited'], $a->awaitEvent());
            self::assertSame(['event' => 'done', 'status' => 'RateLimited'], $b->awaitEvent());
            $row = $db->select()->from('auth_otp_challenges')->where('uuid', $ids[1]->toString())->run()->fetch();
            self::assertNull($row['consumed_at']);
        } finally {
            $a?->close();
            $b?->close();
        }
    }

    private function prepare(string $engine, string $package, array $tables): DatabaseInterface
    {
        if (!databaseAvailable($engine)) {
            self::markTestSkipped('Production database test service is unavailable.');
        }
        $db = database($engine);
        // Strictly isolated synthetic tables, never the application's tables.
        foreach ($tables as $table) {
            $db->execute('DROP TABLE IF EXISTS race_' . $table);
        }
        $schema = file_get_contents(dirname(__DIR__, 2) . '/' . $package . '/resources/schema/' . ($engine === 'mysql' ? 'mysql-8.4.sql' : 'postgresql.sql'));
        self::assertIsString($schema);
        foreach (array_filter(array_map('trim', explode(';', str_replace('auth_', 'race_auth_', $schema)))) as $sql) {
            $db->execute($sql);
        }
        return $db;
    }
}
