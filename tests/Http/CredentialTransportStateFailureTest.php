<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Http\CredentialTransportState;
use PHPUnit\Framework\TestCase;

final class CredentialTransportStateFailureTest extends TestCase
{
    public function testDiscardAttemptsEveryCompensationAndRethrowsFirstExecutedFailure(): void
    {
        $state = new CredentialTransportState();
        $calls = [];
        $failures = [
            'one' => new \RuntimeException('first compensation failed'),
            'two' => new \RuntimeException('second compensation failed'),
        ];

        foreach ($failures as $name => $failure) {
            $state->onDiscard(static function () use (
                &$calls,
                $name,
                $failure,
            ): void {
                $calls[] = $name;
                throw $failure;
            });
        }

        $thrown = null;
        try {
            $state->discardQueued();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        self::assertNotNull($thrown);
        self::assertCount(2, $calls);
        self::assertContains('one', $calls);
        self::assertContains('two', $calls);
        self::assertSame($failures[$calls[0]], $thrown);
    }
}
