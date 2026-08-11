<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http;

use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Denied\RateLimited;
use Componenta\Auth\Denied\UserDisabled;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Event\AuthenticationDenied;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Auth\PublicDeniedReasonInterface;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class DeniedResponseFactoryTest extends TestCase
{
    public function testTrustedAttributesAreNotSerializedByDefault(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with(self::callback(
                static fn(string $json): bool => !str_contains($json, 'secret-audit-value')
                    && str_contains($json, 'invalid_credentials'),
            ))
            ->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);
        $factory = new DeniedResponseFactory($responseFactory);

        self::assertSame(
            $response,
            $factory->create(new DeniedReason(
                'invalid_credentials',
                ['diagnostic' => 'secret-audit-value'],
            )),
        );
    }

    public function testPublicDetailsAreExplicitlyAllowlisted(): void
    {
        $reason = new PublicReasonFixture();
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with(self::callback(static function (string $json): bool {
                $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

                return $decoded === [
                    'error' => 'rate_limited',
                    'details' => ['retry_after' => 30],
                ];
            }))
            ->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->willReturn($response);

        self::assertSame(
            $response,
            (new DeniedResponseFactory($responseFactory))->create($reason),
        );
    }

    public function testNonScalarPublicDetailsAreRejected(): void
    {
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);
        $factory = new DeniedResponseFactory($responseFactory);

        $this->expectException(\UnexpectedValueException::class);
        $factory->create(new InvalidPublicReasonFixture());
    }

    public function testRateLimitMetadataIsNotPublicWithoutExplicitInterface(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('write')
            ->with(self::callback(
                static fn(string $json): bool => !str_contains($json, 'retry_after')
                    && str_contains($json, 'rate_limited'),
            ))
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
            'audit-secret',
            $reason->attributes['diagnostic'] ?? null,
        );
        self::assertSame(
            'moderation-secret',
            $disabled->attributes['reason'] ?? null,
        );
    }
}

final readonly class PublicReasonFixture implements PublicDeniedReasonInterface
{
    public string $code {
        get => 'rate_limited';
    }

    public array $attributes {
        get => ['internal' => 'secret'];
    }

    public array $publicDetails {
        get => ['retry_after' => 30];
    }
}

final readonly class InvalidPublicReasonFixture implements PublicDeniedReasonInterface
{
    public string $code {
        get => 'invalid_public';
    }

    public array $attributes {
        get => [];
    }

    public array $publicDetails {
        get => ['nested' => ['not-allowed']];
    }
}
