<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use PHPUnit\Framework\TestCase;

final class SessionAttributeExtractorTest extends TestCase
{
    public function testInvalidForwardedClientIpDegradesToUnknown(): void
    {
        $attributes = (new SessionAttributeExtractor())->extract(
            new ServerRequestFixture(attributes: [
                'client_ip' => 'not-an-ip',
            ]),
        );

        self::assertSame('', $attributes[DatabaseSessionManager::ATTR_IP]);
    }
}
