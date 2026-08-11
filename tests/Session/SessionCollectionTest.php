<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SessionCollectionTest extends TestCase
{
    public function testStateUsesPropertiesAndPluckSupportsAttributes(): void
    {
        $now = new DateTimeImmutable('@1000');
        $session = new Session(
            id: 'session-1',
            subjectId: Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            expiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
            regenerateAt: $now->modify('+5 minutes'),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
            attributes: ['device' => 'desktop', 'nullable' => null],
        );
        $collection = new SessionCollection([$session]);

        self::assertFalse($collection->empty);
        self::assertSame([$session->id], $collection->pluck());
        self::assertSame(['desktop'], $collection->pluck('device'));
        self::assertNull($session->getAttribute('nullable', 'fallback'));
    }

    public function testUnknownPluckKeyIsRejected(): void
    {
        $this->expectException(\OutOfBoundsException::class);
        $now = new DateTimeImmutable('@1000');
        (new SessionCollection([new Session(
            'session-1',
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        )]))->pluck('missing');
    }
}
