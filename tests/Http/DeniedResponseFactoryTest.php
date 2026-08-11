<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Denied\UserDisabled;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Auth\PublicDeniedReasonInterface;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class DeniedResponseFactoryTest extends TestCase
{
    public function testInternalSubjectAndModerationReasonAreNotSerialized(): void
    {
        [$factory, $body, $headers] = $this->responseHarness(403);
        $reason = new UserDisabled(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            'moderation note',
        );

        (new DeniedResponseFactory($factory, ['user_disabled' => 403]))
            ->create($reason);

        self::assertSame('{"error":"user_disabled"}', $body());
        self::assertSame([
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ], $headers());
    }

    public function testOnlyBoundedScalarPublicDetailsAreSerialized(): void
    {
        [$factory, $body] = $this->responseHarness(401);
        $reason = new PublicDenialFixture(
            code: 'challenge_required',
            attributes: ['internal' => 'never public'],
            publicDetails: [
                'method' => 'otp',
                'attemptsRemaining' => 2,
                'nullable' => null,
                'invalidUtf8' => "\xB1\x31",
                'infinite' => INF,
            ],
        );

        (new DeniedResponseFactory($factory))->create($reason);

        self::assertSame(
            '{"error":"challenge_required","details":{"method":"otp","attemptsRemaining":2,"nullable":null}}',
            $body(),
        );
    }

    public function testMalformedPublicCodeFallsBackToStableMinimalError(): void
    {
        [$factory, $body] = $this->responseHarness(401);

        (new DeniedResponseFactory($factory))->create(new PublicDenialFixture(
            code: "bad\ncode",
            publicDetails: ['message' => "bad\x00value"],
        ));

        self::assertSame('{"error":"authentication_denied"}', $body());
    }

    /**
     * @return array{
     *     ResponseFactoryInterface,
     *     \Closure(): string,
     *     \Closure(): array<string, string>
     * }
     */
    private function responseHarness(int $status): array
    {
        $written = '';
        /** @var array<string, string> $headers */
        $headers = [];
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $value) use (&$written): int {
                $written .= $value;

                return strlen($value);
            },
        );
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->expects(self::exactly(3))
            ->method('withHeader')
            ->willReturnCallback(
                static function (string $name, string $value) use (
                    &$headers,
                    $response,
                ): ResponseInterface {
                    $headers[$name] = $value;

                    return $response;
                },
            );
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects(self::once())
            ->method('createResponse')
            ->with($status)
            ->willReturn($response);

        $bodyReader = static function () use (&$written): string {
            return $written;
        };
        /** @var \Closure(): array<string, string> $headersReader */
        $headersReader = static function () use (&$headers): array {
            return $headers;
        };

        return [$factory, $bodyReader, $headersReader];
    }
}

final readonly class PublicDenialFixture implements PublicDeniedReasonInterface
{
    /**
     * @param array<string, mixed> $attributes
     * @param array<string, bool|float|int|string|null> $publicDetails
     */
    public function __construct(
        public string $code,
        public array $attributes = [],
        public array $publicDetails = [],
    ) {}
}
