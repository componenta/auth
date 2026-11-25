<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Context;
use PHPUnit\Framework\TestCase;

final class ContextTest extends TestCase
{
    public function testWithAttributeReturnsNewContext(): void
    {
        $context = new Context(['ip' => '127.0.0.1', 'nullable' => null]);
        $next = $context->withAttribute('user_agent', 'test');

        self::assertNotSame($context, $next);
        self::assertFalse($context->hasAttribute('user_agent'));
        self::assertSame('test', $next->getAttribute('user_agent'));
        self::assertNull($context->getAttribute('nullable', 'fallback'));
        self::assertSame(['ip' => '127.0.0.1', 'nullable' => null], $context->attributes);
    }

    public function testSerializationExposesOnlyAttributeKeys(): void
    {
        $context = new Context([
            'password' => 'credential-secret',
            'nullable' => null,
        ]);

        $json = json_encode($context, JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('credential-secret', $json);
        self::assertStringContainsString('password', $json);
        self::assertStringContainsString('nullable', $json);
    }
    public function testAddingAnAttributePreservesAnExistingNumericStringKey(): void
    {
        $context = (new Context())->withAttribute('42', 'original');

        $next = $context->withAttribute('another', 'value');

        self::assertSame('original', $next->getAttribute('42'));
        self::assertSame('value', $next->getAttribute('another'));
        self::assertFalse($context->hasAttribute('another'));
    }

    public function testMergingAttributesReplacesNumericStringKeysWithoutReindexing(): void
    {
        $context = (new Context())
            ->withAttribute('42', 'original')
            ->withAttribute('keep', 'unchanged');

        $next = $context->withAttributes(['42' => 'replacement']);

        self::assertSame('replacement', $next->getAttribute('42'));
        self::assertSame(['42' => 'replacement', 'keep' => 'unchanged'], $next->attributes);
        self::assertSame('original', $context->getAttribute('42'));
    }

}
