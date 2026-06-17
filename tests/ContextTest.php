<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Context;
use PHPUnit\Framework\TestCase;

final class ContextTest extends TestCase
{
    public function testWithAttributeReturnsNewContext(): void
    {
        $context = new Context(['ip' => '127.0.0.1']);
        $next = $context->withAttribute('user_agent', 'test');

        self::assertNotSame($context, $next);
        self::assertFalse($context->hasAttribute('user_agent'));
        self::assertSame('test', $next->getAttribute('user_agent'));
        self::assertSame(['ip' => '127.0.0.1'], $context->getAttributes());
    }
}
