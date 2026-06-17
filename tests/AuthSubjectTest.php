<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\AuthSubjectInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class AuthSubjectTest extends TestCase
{
    public function testUsesExplicitAuthSubjectIdWhenAvailable(): void
    {
        $identity = new class implements IdentityInterface, AuthSubjectInterface {
            public UuidInterface $uuid {
                get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
            }

            public function getAuthSubjectId(): int|string
            {
                return 10;
            }
        };

        self::assertSame(10, AuthSubject::id($identity));
    }

    public function testFallsBackToUuidString(): void
    {
        $identity = new class implements IdentityInterface {
            public UuidInterface $uuid {
                get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
            }
        };

        self::assertSame('018f6d5d-3f7a-7a9b-8c2f-123456789abc', AuthSubject::id($identity));
    }
}
