<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Event\AllSessionsTerminated;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Event\SessionsTerminated;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SensitiveSessionObjectsTest extends TestCase
{
    public function testSessionAndLifecycleObjectsDoNotSerializeBearerCredentials(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $createdAt = new DateTimeImmutable('@1000');
        $session = new Session(
            id: 'session-secret',
            subjectId: $subjectId,
            expiresAt: new DateTimeImmutable('@2000'),
            absoluteExpiresAt: new DateTimeImmutable('@3000'),
            regenerateAt: new DateTimeImmutable('@1500'),
            replacedBy: 'replacement-secret',
            createdAt: $createdAt,
            lastActiveAt: new DateTimeImmutable('@1100'),
            attributes: ['private' => 'attribute-secret'],
        );
        $collection = new SessionCollection([$session]);
        $remember = new RememberMeRotation(
            $subjectId,
            'session-secret',
            str_repeat('a', 64),
            new DateTimeImmutable('@3000'),
        );
        $objects = [
            $session,
            $collection,
            $remember,
            new SessionRegenerated('session-secret', 'replacement-secret', $createdAt),
            new SessionsTerminated(['session-secret', 'replacement-secret'], $createdAt),
            new AllSessionsTerminated($subjectId, 'session-secret', $createdAt),
        ];

        foreach ($objects as $object) {
            $json = json_encode($object, JSON_THROW_ON_ERROR);

            self::assertStringNotContainsString('session-secret', $json);
            self::assertStringNotContainsString('replacement-secret', $json);
            self::assertStringNotContainsString('attribute-secret', $json);
        }

        ob_start();
        var_dump($collection);
        $dump = ob_get_clean();

        self::assertIsString($dump);
        self::assertStringNotContainsString('session-secret', $dump);
        self::assertStringNotContainsString('replacement-secret', $dump);
        self::assertStringNotContainsString('attribute-secret', $dump);
    }
}
