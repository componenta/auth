<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Middleware;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\DeniedReason;
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
        $payload = new \stdClass();
        $request = new ServerRequestFixture();
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn($payload);
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')
            ->willReturn(new AuthenticationResult(
                new DeniedReason('fixture'),
                $pendingCredential,
            ));
        $response = $this->createStub(ResponseInterface::class);
        $clearedResponse = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $handledRequest) use ($response): ResponseInterface {
                $state = $handledRequest->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->clear();

                return $response;
            },
        );
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $response)
            ->willReturn($clearedResponse);

        $result = (new AuthenticationMiddleware($extractor, $authenticator, $storage))
            ->process($request, $handler);

        self::assertSame($clearedResponse, $result);
    }

    public function testNestedAuthenticationLayersShareOneTerminalTransportDecision(): void
    {
        $outerPayload = new \stdClass();
        $innerPayload = new \stdClass();
        $pendingCredential = new \stdClass();
        $identity = new AuthenticationIdentityFixture();
        $response = $this->createStub(ResponseInterface::class);
        $clearedResponse = $this->createStub(ResponseInterface::class);

        $outerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $outerExtractor->method('extract')->willReturn($outerPayload);
        $innerExtractor = $this->createStub(PayloadExtractorInterface::class);
        $innerExtractor->method('extract')->willReturn($innerPayload);

        $outerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $outerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity, $pendingCredential),
        );
        $innerAuthenticator = $this->createStub(AuthenticatorInterface::class);
        $innerAuthenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity),
        );

        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $storage->expects(self::once())->method('remove')
            ->with(self::isInstanceOf(ServerRequestInterface::class), $response)
            ->willReturn($clearedResponse);

        $terminal = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($response): ResponseInterface {
                $state = $request->getAttribute(CredentialTransportState::class);
                self::assertInstanceOf(CredentialTransportState::class, $state);
                $state->clear();

                return $response;
            },
        );
        $inner = new AuthenticationMiddleware(
            $innerExtractor,
            $innerAuthenticator,
            $storage,
        );
        $innerHandler = new CallbackRequestHandler(
            static fn(ServerRequestInterface $request): ResponseInterface =>
                $inner->process($request, $terminal),
        );

        $result = (new AuthenticationMiddleware(
            $outerExtractor,
            $outerAuthenticator,
            $storage,
        ))->process(new ServerRequestFixture(), $innerHandler);

        self::assertSame($clearedResponse, $result);
    }

    public function testDeniedResultRemovesStaleIdentityAndSession(): void
    {
        $oldIdentity = new AuthenticationIdentityFixture();
        $oldSession = self::sessionFor($oldIdentity->uuid);
        $request = (new ServerRequestFixture(attributes: [
            IdentityInterface::class => $oldIdentity,
            SessionInterface::class => $oldSession,
        ]));
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $denial = new DeniedReason('invalid_credentials');
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($denial),
        );
        $response = $this->createStub(ResponseInterface::class);
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

    public function testSuccessfulNonSessionResultRemovesStaleDenialAndSession(): void
    {
        $identity = new AuthenticationIdentityFixture();
        $request = new ServerRequestFixture(attributes: [
            DeniedReasonInterface::class => new DeniedReason('old_denial'),
            SessionInterface::class => self::sessionFor($identity->uuid),
        ]);
        $extractor = $this->createStub(PayloadExtractorInterface::class);
        $extractor->method('extract')->willReturn(new \stdClass());
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(
            new AuthenticationResult($identity),
        );
        $response = $this->createStub(ResponseInterface::class);
        $handler = new CallbackRequestHandler(
            static function (ServerRequestInterface $request) use ($identity, $response): ResponseInterface {
                self::assertSame(
                    $identity,
                    $request->getAttribute(IdentityInterface::class),
                );
                self::assertNull(
                    $request->getAttribute(DeniedReasonInterface::class),
                );
                self::assertNull($request->getAttribute(SessionInterface::class));

                return $response;
            },
        );

        self::assertSame(
            $response,
            (new AuthenticationMiddleware($extractor, $authenticator))
                ->process($request, $handler),
        );
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
