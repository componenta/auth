<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Token;

use Componenta\Auth\Token\TokenRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TokenRequestTest extends TestCase
{
    #[DataProvider('controlCharacters')]
    public function testContextRejectsControlCharacters(string $control): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new TokenRequest(
            identity: 'user@example.com',
            purpose: TokenRequest::PURPOSE_MAGIC_LINK,
            context: ['return_to' => '/account' . $control . 'security'],
        );
    }

    /** @return iterable<string, array{string}> */
    public static function controlCharacters(): iterable
    {
        yield 'tab' => ["\t"];
        yield 'line-feed' => ["\n"];
        yield 'carriage-return' => ["\r"];
    }
}
