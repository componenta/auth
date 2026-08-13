<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\RememberMe;

use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
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
}
