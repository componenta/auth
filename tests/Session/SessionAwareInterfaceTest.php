<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Session\SessionAwareInterface;
use PHPUnit\Framework\TestCase;

final class SessionAwareInterfaceTest extends TestCase
{
    public function testExposesSessionCollectionWithoutRequestLocalSessionId(): void
    {
        $interface = new \ReflectionClass(SessionAwareInterface::class);

        self::assertTrue($interface->hasProperty('sessions'));
        self::assertFalse($interface->hasProperty('currentSessionId'));
    }
}
