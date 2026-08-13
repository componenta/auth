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

    public function testNumericStringIdsRemainDistinctStrings(): void
    {
        $first = self::session('1');
        $second = self::session('01');
        $collection = new SessionCollection([$first, $second]);
        $subset = $collection->find(['1', '01']);

        self::assertSame($first, $collection->find('1'));
        self::assertSame($second, $collection->find('01'));
        self::assertInstanceOf(SessionCollection::class, $subset);
        self::assertSame(['1', '01'], $subset->pluck());
    }

    public function testUnknownPluckKeyIsRejected(): void
    {
        $this->expectException(\OutOfBoundsException::class);
        (new SessionCollection([self::session('session-1')]))->pluck('missing');
    }

    private static function session(string $id): Session
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            $id,
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
    }
}
