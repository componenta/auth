<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Strategy\MagicLink\Denied\InvalidToken;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyPayload;
use Componenta\Auth\Token\Token;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MagicLinkStrategyContractTest extends TestCase
{
    private const string TOKEN =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    #[DataProvider('invalidStates')]
    public function testNegativeTokenStatesCollapseToInvalidToken(
        ?Token $token,
        bool $consume,
    ): void {
        $result = $this->strategy(
            new MagicLinkTokenManagerFixture($token, $consume),
            new MagicLinkContractIdentityFixture(),
        )->attempt(new VerifyPayload(self::TOKEN), new Context());

        self::assertInstanceOf(InvalidToken::class, $result->subject);
    }

    public function testValidUnusedTokenAuthenticatesItsSubject(): void
    {
        $identity = new MagicLinkContractIdentityFixture();
        $token = self::token(
            expiresAt: new DateTimeImmutable('@2000'),
            usedAt: null,
        );

        $result = $this->strategy(
            new MagicLinkTokenManagerFixture($token, true),
            $identity,
        )->attempt(new VerifyPayload(self::TOKEN), new Context());

        self::assertSame($identity, $result->subject);
    }

    /** @return iterable<string, array{?Token, bool}> */
    public static function invalidStates(): iterable
    {
        yield 'missing' => [null, false];
        yield 'already used' => [self::token(
            expiresAt: new DateTimeImmutable('@2000'),
            usedAt: new DateTimeImmutable('@900'),
        ), true];
        yield 'expired' => [self::token(
            expiresAt: new DateTimeImmutable('@1000'),
            usedAt: null,
        ), true];
        yield 'lost consume race' => [self::token(
            expiresAt: new DateTimeImmutable('@2000'),
            usedAt: null,
        ), false];
    }

    private function strategy(
        TokenManagerInterface $tokens,
        ?IdentityInterface $identity,
    ): MagicLinkStrategy {
        return new MagicLinkStrategy(
            new MagicLinkContractProviderFixture($identity),
            $tokens,
            new FrozenClock(1000, 'UTC'),
        );
    }

    private static function token(
        DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $usedAt,
    ): Token {
        return new Token(
            id: 1,
            subjectId: Uuid::fromString(MagicLinkContractIdentityFixture::UUID),
            expiresAt: $expiresAt,
            usedAt: $usedAt,
            createdAt: new DateTimeImmutable('@500'),
        );
    }
}

final class MagicLinkTokenManagerFixture implements TokenManagerInterface
{
    public function __construct(
        private ?Token $token,
        private bool $consumeResult,
    ) {}

    public function replaceForSubject(UuidInterface $subjectId): string
    {
        throw new \LogicException('Not used by verification.');
    }

    public function find(string $plainToken): ?Token
    {
        return $this->token;
    }

    public function consume(string $plainToken): bool
    {
        return $this->consumeResult;
    }

    public function cleanup(int $limit = 1000): int
    {
        return 0;
    }
}

final readonly class MagicLinkContractProviderFixture implements UserProviderInterface
{
    public function __construct(private ?IdentityInterface $identity) {}

    public function findByIdentity(string $identity): ?IdentityInterface
    {
        return null;
    }

    public function findByUuid(UuidInterface $uuid): ?IdentityInterface
    {
        return $this->identity;
    }
}

final class MagicLinkContractIdentityFixture implements IdentityInterface
{
    public const string UUID = '018f6d5d-3f7a-7a9b-8c2f-123456789abc';

    public UuidInterface $uuid {
        get => Uuid::fromString(self::UUID);
    }
}
