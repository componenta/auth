<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Security;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\Authenticator;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Event\SessionRegenerated;
use Componenta\Auth\Http\DeniedResponseFactory;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\Http\Strategy\Password\LoginHandler;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\Http\Transport\CookieTransport;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeCompromise;
use Componenta\Auth\RememberMe\RememberMeRegenerationListener;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionCollection;
use Componenta\Auth\Session\SessionIdGeneratorInterface;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Auth\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;

final class CredentialTraceTest extends TestCase
{
    public function testSessionPayloadValidationDoesNotExposeCredential(): void
    {
        $exception = $this->capture(static function (): void {
            new SessionPayload("session-payload-secret\n");
        });

        self::assertTraceHides($exception, 'session-payload-secret');
    }

    public function testRememberRotationValidationDoesNotExposeSessionCredential(): void
    {
        $exception = $this->capture(function (): void {
            new RememberMeRotation(
                self::subjectId(),
                "rotation-session-secret\n",
                str_repeat('a', 32) . '.' . str_repeat('b', 64),
                new \DateTimeImmutable('@2000'),
            );
        });

        self::assertTraceHides($exception, 'rotation-session-secret');
    }

    public function testInvalidAuthenticationResultDoesNotExposePrivateObjects(): void
    {
        $exception = $this->capture(static function (): void {
            new AuthenticationResult(
                new DeniedReason('invalid_credentials', [
                    'private' => 'denial-result-secret',
                ]),
                new SessionPayload('result-session-secret'),
            );
        });

        self::assertTraceHides(
            $exception,
            'denial-result-secret',
            'result-session-secret',
        );
    }

    public function testPasswordRequestAndContextDoNotAppearInTrace(): void
    {
        $handler = new LoginHandler(
            new PasswordExtractor(),
            new Authenticator(new CredentialTraceThrowingStrategy()),
            $this->createStub(\Componenta\Auth\Session\SessionManagerInterface::class),
            $this->createStub(PayloadStorageInterface::class),
            $this->createStub(DeniedResponseFactoryInterface::class),
            $this->createStub(ResponseFactoryInterface::class),
        );
        $request = new ServerRequestFixture(parsedBody: [
            'email' => 'user@example.com',
            'password' => 'request-password-secret',
        ]);

        $exception = $this->capture(
            static fn() => $handler->handle($request),
        );

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertTraceHides($exception, 'request-password-secret');
    }

    public function testSessionCreationDoesNotExposeArbitraryAttributes(): void
    {
        $database = $this->createStub(DatabaseInterface::class);
        $database->method('insert')->willReturnCallback(
            static fn() => throw new CredentialTraceFailure(
                'session persistence failed',
            ),
        );
        $idGenerator = $this->createStub(SessionIdGeneratorInterface::class);
        $idGenerator->method('generate')->willReturn('generated-session-id');
        $manager = new DatabaseSessionManager(
            $database,
            $idGenerator,
            new FrozenClock(1000, 'UTC'),
            new EventDispatcher(new PriorityListenerProvider()),
        );

        $exception = $this->capture(static function () use ($manager): void {
            $manager->create(self::subjectId(), [
                DatabaseSessionManager::ATTR_IP => '127.0.0.1',
                DatabaseSessionManager::ATTR_USER_AGENT => 'trace-test',
                'private' => 'session-attribute-secret',
            ]);
        });

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertTraceHides($exception, 'session-attribute-secret');
    }

    public function testSessionConstructorDoesNotExposeAttributes(): void
    {
        $exception = $this->capture(static function (): void {
            $now = new \DateTimeImmutable('@1000');
            new Session(
                id: 'session-id',
                subjectId: self::subjectId(),
                expiresAt: $now,
                absoluteExpiresAt: $now->modify('+1 hour'),
                regenerateAt: $now,
                replacedBy: null,
                createdAt: $now,
                lastActiveAt: $now,
                attributes: ['private' => 'session-constructor-secret'],
            );
        });

        self::assertTraceHides($exception, 'session-constructor-secret');
    }

    public function testSessionCollectionDoesNotExposePresentedIdsOnValidationFailure(): void
    {
        $collection = new SessionCollection();
        $exception = $this->capture(static function () use ($collection): void {
            // Deliberately crosses the static contract to exercise the public
            // runtime validation path for untyped/external PHP callers.
            $collection->find(['collection-session-secret', 42]);
        });

        self::assertTraceHides($exception, 'collection-session-secret');
    }

    public function testOtpStoreFailureDoesNotExposePlainCode(): void
    {
        $database = $this->createStub(DatabaseInterface::class);
        $database->method('insert')->willReturnCallback(
            static fn() => throw new CredentialTraceFailure('database failed'),
        );
        $store = new DatabaseCodeStore($database, str_repeat('k', 32));
        $code = new StoredCode(
            self::subjectId(),
            '654321',
            'user@example.com',
            2000,
        );

        $exception = $this->capture(
            static fn() => $store->store($code),
        );

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertTraceHides($exception, '654321');
    }

    public function testDatabaseConstructorDoesNotExposeDatabaseObject(): void
    {
        $database = $this->createStub(DatabaseInterface::class);
        $exception = $this->capture(
            static fn() => new DatabaseCodeStore($database, 'short'),
        );

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertPackageTraceDoesNotExposeObject(
            $exception,
            DatabaseInterface::class,
        );
    }

    public function testDatabaseHelperDoesNotExposeDatabaseObject(): void
    {
        $database = $this->createStub(DatabaseInterface::class);
        $database->method('select')->willReturnCallback(
            static fn() => throw new CredentialTraceFailure('select failed'),
        );
        $store = new DatabaseCodeStore($database, str_repeat('k', 32));

        $exception = $this->capture(
            static fn() => $store->verifyAndConsume(
                'user@example.com',
                '123456',
                1000,
                5,
            ),
        );

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertPackageTraceDoesNotExposeObject(
            $exception,
            DatabaseInterface::class,
        );
    }

    public function testDatabaseTransactionCallbackDoesNotExposeDatabaseObject(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped(
                'pdo_sqlite is required for storage integration tests.',
            );
        }

        $database = SqliteDatabaseFixture::create();
        $store = new DatabaseRefreshTokenStore($database);
        $token = new RefreshToken(
            str_repeat('a', 64),
            self::subjectId(),
            str_repeat('b', 64),
            2000,
        );

        // Deliberately omit the refresh schema so the exception is created
        // inside the transaction callback while the DatabaseInterface argument
        // is present on the package-owned closure frame.
        $exception = $this->capture(
            static fn() => $store->storeInitial($token),
        );

        self::assertPackageTraceDoesNotExposeObject(
            $exception,
            DatabaseInterface::class,
        );
    }

    public function testRefreshStoreValidationDoesNotExposeBearerObject(): void
    {
        $store = new DatabaseRefreshTokenStore(
            $this->createStub(DatabaseInterface::class),
        );
        $token = new RefreshToken(
            str_repeat('a', 64),
            self::subjectId(),
            str_repeat('b', 64),
            2000,
            1000,
        );

        $exception = $this->capture(
            static fn() => $store->storeInitial($token),
        );

        self::assertTraceHides(
            $exception,
            str_repeat('a', 64),
            str_repeat('b', 64),
        );
    }

    public function testInvalidCookieExtractionDoesNotExposeCookieCredential(): void
    {
        $transport = new CookieTransport();
        $request = new ServerRequestFixture(cookieParams: [
            'sid' => "cookie-session-secret\n",
        ]);

        $exception = $this->capture(
            static fn() => $transport->extract($request),
        );

        self::assertTraceHides($exception, 'cookie-session-secret');
    }

    public function testDeniedResponseFailureDoesNotExposePrivateAttributes(): void
    {
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturnCallback(
            static fn() => throw new CredentialTraceFailure(
                'response allocation failed',
            ),
        );
        $factory = new DeniedResponseFactory($responses);
        $reason = new DeniedReason('authentication_denied', [
            'private' => 'denied-factory-secret',
        ]);

        $exception = $this->capture(
            static fn() => $factory->create($reason),
        );

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertTraceHides($exception, 'denied-factory-secret');
    }

    public function testCriticalSessionEventFailureDoesNotExposeSessionIds(): void
    {
        $provider = new PriorityListenerProvider();
        $provider->addListener(new RememberMeRegenerationListener(
            new CredentialTraceRememberManager(),
        ));
        $dispatcher = new EventDispatcher($provider);
        $event = new SessionRegenerated(
            'event-old-session-secret',
            'event-new-session-secret',
            new \DateTimeImmutable('@1000'),
        );

        $exception = $this->capture(
            static fn() => $dispatcher->dispatchCritical($event),
        );

        self::assertInstanceOf(CredentialTraceFailure::class, $exception);
        self::assertTraceHides(
            $exception,
            'event-old-session-secret',
            'event-new-session-secret',
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

    private static function assertTraceHides(
        \Throwable $exception,
        string ...$secrets,
    ): void {
        foreach ($secrets as $secret) {
            /** @var array<int, true> $seen */
            $seen = [];

            foreach ($exception->getTrace() as $frame) {
                foreach ($frame['args'] ?? [] as $argument) {
                    self::assertFalse(
                        self::traceValueContains($argument, $secret, $seen),
                        'Exception trace exposed sensitive value.',
                    );
                }
            }
        }
    }

    /** @param array<int, true> $seen */
    private static function traceValueContains(
        mixed $value,
        string $secret,
        array &$seen,
        int $depth = 0,
    ): bool {
        if ($depth > 16 || $value instanceof \SensitiveParameterValue) {
            return false;
        }

        if (is_string($value)) {
            return str_contains($value, $secret);
        }

        if (is_array($value)) {
            foreach ($value as $item) {
                if (self::traceValueContains($item, $secret, $seen, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }

        if (!is_object($value)) {
            return false;
        }

        $objectId = spl_object_id($value);

        if (isset($seen[$objectId])) {
            return false;
        }

        $seen[$objectId] = true;

        foreach ((array) $value as $item) {
            if (self::traceValueContains($item, $secret, $seen, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    /** @param class-string $objectClass */
    private static function assertPackageTraceDoesNotExposeObject(
        \Throwable $exception,
        string $objectClass,
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
                self::assertNotInstanceOf($objectClass, $argument);
            }
        }

        self::assertGreaterThan(0, $checkedFrames);
    }

    private static function subjectId(): UuidInterface
    {
        return Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final class CredentialTraceFailure extends \RuntimeException
{
}

final readonly class CredentialTraceThrowingStrategy implements AuthenticationStrategyInterface
{
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return true;
    }

    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        throw new CredentialTraceFailure('strategy failed');
    }
}

final readonly class CredentialTraceRememberManager implements RememberMeTokenManagerInterface
{
    public function create(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $sessionId,
    ): string {
        return str_repeat('a', 32) . '.' . str_repeat('b', 64);
    }

    public function rotate(
        #[\SensitiveParameter]
        string $plainToken,
    ): RememberMeRotation|RememberMeCompromise|null {
        return null;
    }

    public function bindRotation(
        #[\SensitiveParameter]
        RememberMeRotation $rotation,
        #[\SensitiveParameter]
        string $newSessionId,
    ): bool {
        return false;
    }

    public function revoke(
        #[\SensitiveParameter]
        string $plainToken,
    ): void {}

    public function revokeForSession(
        #[\SensitiveParameter]
        string $sessionId,
    ): void {}

    public function revokeForSessions(
        #[\SensitiveParameter]
        iterable $sessionIds,
    ): void {}

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        ?string $exceptSessionId = null,
    ): void {}

    public function updateSessionId(
        #[\SensitiveParameter]
        string $oldSessionId,
        #[\SensitiveParameter]
        string $newSessionId,
    ): void {
        throw new CredentialTraceFailure('remember listener failed');
    }

    public function cleanup(int $limit = 1000): int
    {
        return 0;
    }
}
