<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Denied\RateLimited;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Middleware\AuthenticationMiddleware;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionInterface;
use Componenta\Auth\Tests\Support\CallbackRequestHandler;
use Componenta\Auth\Tests\Support\ServerRequestFixture;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthenticationMiddlewareTest extends TestCase
{
    public function testDownstreamCredentialClearCancelsPendingRotation(): void
    {
        $pendingCredential = new \stdClass();
        $identity = new AuthenticationIdentityFixture();
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, $pendingCredential),
        );
        $response = $this->responseStub();
        $clearedResponse = $this->responseStub();
        $storage = $this->createMock(PayloadStorageInterface::class);
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $handledRequest) use ($response, $storage): ResponseInterface {
                $state = $handledRequest->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->clear($storage);

                return $response;
            },
        );
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $response)
            ->willReturn($clearedResponse);

        self::assertSame(
            $clearedResponse,
            (new AuthenticationMiddleware($extractor, $authenticator, $storage))
                ->process(new ServerRequestFixture(), $handler),
        );
    }

    public function testNestedAuthenticationLayersPreserveDifferentStorages(): void
    {
        $identity = new AuthenticationIdentityFixture();
        $outerCredential = new \stdClass();
        $innerCredential = new \stdClass();
        $response = $this->responseStub();
        $afterOuter = $this->responseStub();
        $afterInner = $this->responseStub();
        $outerStorage = $this->createMock(PayloadStorageInterface::class);
        $innerStorage = $this->createMock(PayloadStorageInterface::class);
        $outerStorage->expects(self::once())->method('store')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $response, $outerCredential)
            ->willReturn($afterOuter);
        $innerStorage->expects(self::once())->method('store')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $afterOuter, $innerCredential)
            ->willReturn($afterInner);
        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn(new \stdClass());
        $innerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $innerExtractor->method('extract')->willReturn(new \stdClass());
        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, $outerCredential),
        );
        $innerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $innerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, $innerCredential),
        );
        $terminal = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface => $response,
        );
        $inner = new AuthenticationMiddleware(
            $innerExtractor,
            $innerAuthenticator,
            $innerStorage,
        );
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        self::assertSame(
            $afterInner,
            (new AuthenticationMiddleware(
                $outerExtractor,
                $outerAuthenticator,
                $outerStorage,
            ))->process(new ServerRequestFixture(), $innerHandler),
        );
    }

    public function testTerminalNestedDenialCannotBeOverwrittenByLaterSuccess(): void
    {
        $denial = new RateLimited(30);
        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn(new \stdClass());
        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($denial),
        );
        $innerExtractor = $this->createMock(PayloadExtractorInterface::class);
        $innerExtractor->expects(self::never())->method('extract');
        $innerAuthenticator = $this->createMock(AuthenticatorInterface::class);
        $innerAuthenticator->expects(self::never())->method('attempt');
        $response = $this->responseStub();
        $terminal = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($denial, $response): ResponseInterface {
                self::assertSame(
                    $denial,
                    $request->getAttribute(DeniedReasonInterface::class),
                );
                self::assertNull($request->getAttribute(IdentityInterface::class));

                return $response;
            },
        );
        $inner = new AuthenticationMiddleware($innerExtractor, $innerAuthenticator);
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($outerExtractor, $outerAuthenticator))
                ->process(new ServerRequestFixture(), $innerHandler),
        );
    }

    public function testLaterNestedDenialCancelsEarlierQueuedCredential(): void
    {
        $identity = new AuthenticationIdentityFixture();
        $credential = new \stdClass();
        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn(new \stdClass());
        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, $credential),
        );
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $innerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $innerExtractor->method('extract')->willReturn(new \stdClass());
        $denial = new RateLimited(30);
        $innerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $innerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($denial),
        );
        $response = $this->responseStub();
        $terminal = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($denial, $response): ResponseInterface {
                self::assertSame(
                    $denial,
                    $request->getAttribute(DeniedReasonInterface::class),
                );
                self::assertNull($request->getAttribute(IdentityInterface::class));

                return $response;
            },
        );
        $inner = new AuthenticationMiddleware($innerExtractor, $innerAuthenticator);
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware(
                $outerExtractor,
                $outerAuthenticator,
                $storage,
            ))->process(new ServerRequestFixture(), $innerHandler),
        );
    }

    public function testNestedDifferentPrincipalsFailClosed(): void
    {
        $outerIdentity = new AuthenticationIdentityFixture();
        $innerIdentity = new OtherAuthenticationIdentityFixture();
        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn(new \stdClass());
        $innerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $innerExtractor->method('extract')->willReturn(new \stdClass());
        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($outerIdentity),
        );
        $innerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $innerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($innerIdentity),
        );
        $response = $this->responseStub();
        $terminal = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($response): ResponseInterface {
                self::assertNull($request->getAttribute(IdentityInterface::class));
                self::assertInstanceOf(
                    InvalidCredentials::class,
                    $request->getAttribute(DeniedReasonInterface::class),
                );

                return $response;
            },
        );
        $inner = new AuthenticationMiddleware($innerExtractor, $innerAuthenticator);
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($outerExtractor, $outerAuthenticator))
                ->process(new ServerRequestFixture(), $innerHandler),
        );
    }

    public function testSamePrincipalNestedSuccessPreservesExistingSession(): void
    {
        $identity = new AuthenticationIdentityFixture();
        $session = self::sessionFor($identity->uuid);
        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn(new \stdClass());
        $innerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $innerExtractor->method('extract')->willReturn(new \stdClass());
        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, session: $session),
        );
        $innerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $innerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity),
        );
        $response = $this->responseStub();
        $terminal = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($session, $response): ResponseInterface {
                self::assertSame(
                    $session,
                    $request->getAttribute(SessionInterface::class),
                );

                return $response;
            },
        );
        $inner = new AuthenticationMiddleware($innerExtractor, $innerAuthenticator);
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($outerExtractor, $outerAuthenticator))
                ->process(new ServerRequestFixture(), $innerHandler),
        );
    }

    public function testCredentialMutationWithoutStorageFailsBeforeDownstream(): void
    {
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult(
                new AuthenticationIdentityFixture(),
                new \stdClass(),
            ),
        );
        $handler = new CallbackRequestHandler(
            static function (): ResponseInterface {
                self::fail('Downstream handler must not run without required credential storage.');
            },
        );

        $this->expectException(\LogicException::class);
        (new AuthenticationMiddleware($extractor, $authenticator))
            ->process(new ServerRequestFixture(), $handler);
    }

    public function testDeniedResultRemovesStaleIdentityAndSession(): void
    {
        $oldIdentity = new AuthenticationIdentityFixture();
        $oldSession = self::sessionFor($oldIdentity->uuid);
        $request = new ServerRequestFixture(attributes: [
            IdentityInterface::class => $oldIdentity,
            SessionInterface::class => $oldSession,
        ]);
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $denial = new DeniedReason('invalid_credentials');
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($denial),
        );
        $response = $this->responseStub();
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($denial, $response): ResponseInterface {
                self::assertNull($request->getAttribute(IdentityInterface::class));
                self::assertNull($request->getAttribute(SessionInterface::class));
                self::assertSame(
                    $denial,
                    $request->getAttribute(DeniedReasonInterface::class),
                );

                return $response;
            },
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($extractor, $authenticator))
                ->process($request, $handler),
        );
    }

    public function testExistingDenialSkipsAuthenticationAndRemainsTerminal(): void
    {
        $denial = new DeniedReason('old_denial');
        $request = new ServerRequestFixture(attributes: [
            DeniedReasonInterface::class => $denial,
        ]);
        $extractor = $this->createMock(PayloadExtractorInterface::class);
        $extractor->expects(self::never())->method('extract');
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->expects(self::never())->method('attempt');
        $response = $this->responseStub();
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($denial, $response): ResponseInterface {
                self::assertSame(
                    $denial,
                    $request->getAttribute(DeniedReasonInterface::class),
                );

                return $response;
            },
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($extractor, $authenticator))
                ->process($request, $handler),
        );
    }

    private function responseStub(): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();

        return $response;
    }

    private static function sessionFor(UuidInterface $subjectId): SessionInterface
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            id: 'session-id',
            subjectId: $subjectId,
            expiresAt: $now->modify('+30 minutes'),
            absoluteExpiresAt: $now->modify('+8 hours'),
            regenerateAt: $now->modify('+5 minutes'),
            replacedBy: null,
            createdAt: $now,
            lastActiveAt: $now,
        );
    }
}

final class AuthenticationIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
    }
}

final class OtherAuthenticationIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-abcdefabcdef');
    }
}
