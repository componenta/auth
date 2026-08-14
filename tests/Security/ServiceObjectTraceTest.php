<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Security;

use Componenta\Auth\Event\EventInterface;
use Componenta\Auth\Event\EventListenerInterface;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\PayloadStorageInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ServiceObjectTraceTest extends TestCase
{
    public function testListenerValidationDoesNotExposeApplicationListenerObject(): void
    {
        $listener = new TraceSensitiveListener('listener-object-secret');
        $provider = new PriorityListenerProvider();
        $exception = $this->capture(
            static fn() => $provider->addListener($listener),
        );

        self::assertInstanceOf(ServiceObjectTraceFailure::class, $exception);
        self::assertPackageFramesDoNotContainObject($exception, $listener);
    }

    public function testCredentialClearFailureDoesNotExposeStorageObject(): void
    {
        $storage = new TraceSensitiveStorage('storage-object-secret');
        $state = new CredentialTransportState();
        $state->onDiscard(
            static fn() => throw new ServiceObjectTraceFailure(
                'compensation failed',
            ),
        );
        $exception = $this->capture(
            static fn() => $state->clear($storage),
        );

        self::assertInstanceOf(ServiceObjectTraceFailure::class, $exception);
        self::assertPackageFramesDoNotContainObject($exception, $storage);
    }

    public function testImmediateDiscardCallbackDoesNotExposeCapturedClosure(): void
    {
        $storage = new TraceSensitiveStorage('storage-object-secret');
        $state = new CredentialTransportState();
        $state->clear($storage);
        $secret = 'discard-callback-secret';
        $callback = static function () use ($secret): void {
            throw new ServiceObjectTraceFailure(sprintf(
                'discard callback failed with %d captured bytes',
                strlen($secret),
            ));
        };
        $exception = $this->capture(
            static fn() => $state->onDiscard($callback),
        );

        self::assertInstanceOf(ServiceObjectTraceFailure::class, $exception);
        self::assertPackageFramesDoNotContainObject($exception, $callback);
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

final class ServiceObjectTraceFailure extends \RuntimeException
{
}

final class TraceSensitiveListener implements EventListenerInterface
{
    public function __construct(public string $secret) {}

    /** @var non-empty-list<class-string<EventInterface>> */
    public array $events {
        get => throw new ServiceObjectTraceFailure('listener events failed');
    }

    public function handleEvent(
        #[\SensitiveParameter]
        EventInterface $event,
    ): void {}
}

final readonly class TraceSensitiveStorage implements PayloadStorageInterface
{
    public function __construct(public string $secret) {}

    public function store(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        object $payload,
    ): ResponseInterface {
        return $response;
    }

    public function remove(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return $response;
    }
}
