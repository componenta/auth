<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Session\SessionAwareInterface;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionCollectionInterface;
use PHPUnit\Framework\TestCase;

final class SessionAwareInterfaceTest extends TestCase
{
    public function testExposesSessionsWithoutRequestLocalCurrentSession(): void
    {
        $sessions = new SessionCollection();
        $identity = new readonly class($sessions) implements SessionAwareInterface {
            public function __construct(
                public SessionCollectionInterface $sessions,
            ) {}
        };

        self::assertSame($sessions, $identity->sessions);
        self::assertFalse(
            (new \ReflectionClass(SessionAwareInterface::class))
                ->hasProperty('currentSessionId'),
        );
    }
}
