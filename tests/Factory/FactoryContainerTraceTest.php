<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Factory;

use Componenta\Auth\Exception\AuthenticatorConfigurationException;
use Componenta\Auth\Factory\AuthenticatorFactory;
use Componenta\Auth\Factory\DatabaseSessionManagerFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

final class FactoryContainerTraceTest extends TestCase
{
    public function testSimpleFactoryDoesNotExposeContainerStateInTrace(): void
    {
        $container = new FactoryTraceContainer('factory-container-secret');
        $exception = $this->capture(
            static fn() => (new AuthenticatorFactory())($container),
        );

        self::assertInstanceOf(AuthenticatorConfigurationException::class, $exception);
        self::assertFactoryTraceHides(
            $exception,
            AuthenticatorFactory::class,
            $container->secret,
        );
    }

    public function testPrivateFactoryHelperDoesNotExposeContainerStateInTrace(): void
    {
        $container = new FactoryTraceContainer('factory-helper-secret');
        $exception = $this->capture(
            static fn() => (new DatabaseSessionManagerFactory())($container),
        );

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertFactoryTraceHides(
            $exception,
            DatabaseSessionManagerFactory::class,
            $container->secret,
        );
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

    /** @param class-string $factoryClass */
    private static function assertFactoryTraceHides(
        \Throwable $exception,
        string $factoryClass,
        string $secret,
    ): void {
        $frames = array_values(array_filter(
            $exception->getTrace(),
            static fn(array $frame): bool => ($frame['class'] ?? null) === $factoryClass,
        ));

        self::assertNotEmpty($frames);
        self::assertStringNotContainsString(
            $secret,
            var_export($frames, true),
        );
    }
}

final readonly class FactoryTraceContainer implements ContainerInterface
{
    public function __construct(public string $secret) {}

    public function get(string $id): mixed
    {
        return new \stdClass();
    }

    public function has(string $id): bool
    {
        return false;
    }
}
