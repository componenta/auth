<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Session;

use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class SessionCollectionTraceTest extends TestCase
{
    public function testFilterDoesNotExposeApplicationCallbackObject(): void
    {
        $collection = new SessionCollection([
            new TraceSession('session-object-secret'),
        ]);
        $secret = 'filter-callback-secret';
        $callback = static function (SessionInterface $session) use ($secret): bool {
            throw new SessionCollectionTraceFailure(sprintf(
                'filter failed for %s with %d captured bytes',
                $session->id,
                strlen($secret),
            ));
        };
        $exception = $this->capture(
            static fn() => $collection->filter($callback),
        );

        self::assertInstanceOf(SessionCollectionTraceFailure::class, $exception);
        self::assertPackageFramesDoNotContainObject($exception, $callback);
    }

    public function testPluckDoesNotExposeCustomSessionObject(): void
    {
        $session = new TraceSession('pluck-session-object-secret');
        $collection = new SessionCollection([$session]);
        $exception = $this->capture(
            static fn() => $collection->pluck('custom'),
        );

        self::assertInstanceOf(SessionCollectionTraceFailure::class, $exception);
        self::assertPackageFramesDoNotContainObject($exception, $session);
    }

    private function capture(
        #[\SensitiveParameter]
        \Closure $callback,
    ): \Throwable {
        $previous = ini_get('zend.exception_ignore_args');
        self::assertIsString($previous);
        self::assertNotFalse(ini_set('zend.exception_ignore_args', '0'));
        $thrown = null;

        try {
            $callback();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }

        self::assertNotNull($thrown);

        return $thrown;
    }

    private static function assertPackageFramesDoNotContainObject(
        \Throwable $exception,
        object $sensitiveObject,
    ): void {
        $checkedFrames = 0;

        foreach ($exception->getTrace() as $frame) {
            $class = $frame['class'] ?? null;

            if (
                !is_string($class)
                || !str_starts_with($class, 'Componenta\\Auth\\')
                || str_starts_with($class, 'Componenta\\Auth\\Tests\\')
            ) {
                continue;
            }

            ++$checkedFrames;

            foreach ($frame['args'] ?? [] as $argument) {
                self::assertNotSame($sensitiveObject, $argument);
            }
        }

        self::assertGreaterThan(0, $checkedFrames);
    }
}

final class SessionCollectionTraceFailure extends \RuntimeException
{
}

final class TraceSession implements SessionInterface
{
    public string $id = 'trace-session';
    public UuidInterface $subjectId;
    public \DateTimeImmutable $expiresAt;
    public \DateTimeImmutable $absoluteExpiresAt;
    public \DateTimeImmutable $regenerateAt;
    public ?string $replacedBy = null;
    public \DateTimeImmutable $createdAt;
    public \DateTimeImmutable $lastActiveAt;
    /** @var array<string, mixed> */
    public array $attributes = [];

    public function __construct(public string $secret)
    {
        $this->subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $this->createdAt = new \DateTimeImmutable('@1000');
        $this->expiresAt = new \DateTimeImmutable('@2000');
        $this->absoluteExpiresAt = new \DateTimeImmutable('@3000');
        $this->regenerateAt = new \DateTimeImmutable('@1500');
        $this->lastActiveAt = new \DateTimeImmutable('@1100');
    }

    public function hasAttribute(string $name): bool
    {
        throw new SessionCollectionTraceFailure('session attribute lookup failed');
    }

    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $default;
    }
}
