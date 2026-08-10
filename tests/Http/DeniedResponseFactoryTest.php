<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Denied\UserDisabled;
use Componenta\Auth\Http\DeniedResponseFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class DeniedResponseFactoryTest extends TestCase
{
    public function testInternalUserIdAndModerationReasonAreNotSerialized(): void
    {
        $written = null;
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $body) use (&$written): int {
            $written = $body;
            return strlen($body);
        });
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->method('createResponse')->with(403)->willReturn($response);

        (new DeniedResponseFactory($factory, ['user_disabled' => 403]))
            ->create(new UserDisabled('internal-user-42', 'moderation note'));

        self::assertSame('{"error":"user_disabled"}', $written);
    }
}
