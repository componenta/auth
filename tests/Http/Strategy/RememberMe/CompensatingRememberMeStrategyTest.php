<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\RememberMe;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\Strategy\RememberMe\CompensatingRememberMeStrategy;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\Session;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class CompensatingRememberMeStrategyTest extends TestCase
{
    public function testDiscardRevokesSuccessorAndTerminatesUnpublishedSession(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $session = self::session($subjectId);
        $successor = str_repeat('a', 64);
        $delegate = $this->createStub(AuthenticationStrategyInterface::class);
        $delegate->method('supports')->willReturn(true);
        $delegate->method('attempt')->willReturn(new AuthenticationResult(
            new CompensatingRememberIdentityFixture($subjectId),
            new SessionPayload($session->id, $successor),
            $session,
        ));
        $tokens = $this->createMock(RememberMeTokenManagerInterface::class);
        $tokens->expects(self::once())->method('revoke')->with($successor);
        $sessions = $this->createMock(SessionManagerInterface::class);
        $sessions->expects(self::once())->method('terminate')->with($session->id);
        $state = new CredentialTransportState();
        $context = new Context([CredentialTransportState::class => $state]);
        $strategy = new CompensatingRememberMeStrategy($delegate, $tokens, $sessions);

        $result = $strategy->attempt(new \stdClass(), $context);
        self::assertSame($session, $result->session);

        $state->discardQueued();
    }

    public function testSuccessfulResultIsPreservedWhenNoTransportStateExists(): void
    {
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $session = self::session($subjectId);
        $result = new AuthenticationResult(
            new CompensatingRememberIdentityFixture($subjectId),
            new SessionPayload($session->id, str_repeat('b', 64)),
            $session,
        );
        $delegate = $this->createStub(AuthenticationStrategyInterface::class);
        $delegate->method('attempt')->willReturn($result);
        $strategy = new CompensatingRememberMeStrategy(
            $delegate,
            $this->createStub(RememberMeTokenManagerInterface::class),
            $this->createStub(SessionManagerInterface::class),
        );

        self::assertSame($result, $strategy->attempt(new \stdClass(), new Context()));
    }

    private static function session(UuidInterface $subjectId): Session
    {
        $now = new DateTimeImmutable('@1000');

        return new Session(
            'session-id',
            $subjectId,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
            $now->modify('+5 minutes'),
            null,
            $now,
            $now,
        );
    }
}

final readonly class CompensatingRememberIdentityFixture implements IdentityInterface
{
    public function __construct(public UuidInterface $uuid) {}
}
