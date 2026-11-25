<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Denied\RateLimited;
use PHPUnit\Framework\TestCase;

final class RateLimitedTest extends TestCase
{
    public function testNegativeUpdateIsRejectedWithoutChangingThePreviousDuration(): void
    {
        $reason = new RateLimited(60);

        try {
            $reason->retryAfter = -1;
            self::fail('A negative retry duration was accepted.');
        } catch (\InvalidArgumentException) {
            self::assertSame(60, $reason->retryAfter);
            self::assertSame(['retry_after' => 60], $reason->attributes);
        }
    }

    public function testValidUpdateRemainsSupported(): void
    {
        $reason = new RateLimited(60);

        $reason->retryAfter = 0;

        self::assertSame(0, $reason->retryAfter);
        self::assertSame(['retry_after' => 0], $reason->attributes);
    }

    public function testNegativeInitialDurationIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RateLimited(-1);
    }
}
