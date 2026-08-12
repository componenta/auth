<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Denied\RateLimited;
use Componenta\Auth\Denied\UserDisabled;
use Componenta\Auth\Event\AuthenticationDenied;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class DeniedResponseFactoryTest extends TestCase
{
    public function testTrustedAttributesAreNeverSerializedByDefault(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with(self::callback(static function (string $json): bool {
                $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

                return $decoded === ['error' => 'invalid_credentials'];
            }))
            ->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);

        self::assertSame(
            $response,
            (new DeniedResponseFactory($responseFactory))->create(
                new DeniedReason(
                    'invalid_credentials',
                    ['diagnostic' => 'secret-audit-value'],
                ),
            ),
        );
    }

    public function testRateLimitMetadataRemainsAuditOnly(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with('{"error":"rate_limited"}')
            ->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);

        (new DeniedResponseFactory($responseFactory))->create(
            new RateLimited(30),
        );
    }

    public function testInvalidReasonCodeFallsBackToStablePublicCode(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with('{"error":"authentication_denied"}')
            ->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);

        (new DeniedResponseFactory($responseFactory))->create(
            new DeniedReason('INVALID CODE', ['secret' => 'value']),
        );
    }

    public function testAuditObjectsDoNotSerializeTrustedReasonAttributes(): void
    {
        $reason = new DeniedReason(
            'invalid_credentials',
            ['diagnostic' => 'audit-secret'],
        );
        $event = new AuthenticationDenied(
            $reason,
            'SensitivePayload',
            new DateTimeImmutable('@1000'),
        );
        $disabled = new UserDisabled(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            'moderation-secret',
        );

        foreach ([$reason, $event, $disabled] as $value) {
            $json = json_encode($value, JSON_THROW_ON_ERROR);

            self::assertStringNotContainsString('audit-secret', $json);
            self::assertStringNotContainsString('moderation-secret', $json);
        }

        self::assertSame(
            '{"code":"rate_limited"}',
            json_encode(new RateLimited(30), JSON_THROW_ON_ERROR),
        );
        self::assertSame(
            'audit-secret',
            $reason->attributes['diagnostic'] ?? null,
        );
        self::assertSame(
            'moderation-secret',
            $disabled->attributes['reason'] ?? null,
        );
    }
}
