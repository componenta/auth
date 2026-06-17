<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\Strategy\MagicLink\Denied\InvalidToken;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\DateTimeFactoryInterface;

/**
 * Authenticates a user via a database-backed magic link token.
 *
 * Handles the verify step of the magic link flow:
 * finds token, checks state (expired/used), consumes atomically, loads user.
 *
 * All negative outcomes collapse to {@see InvalidToken} on the wire to
 * prevent external observers from distinguishing "never existed" from
 * "expired" or "already used". Callers that need the specific failure
 * cause for logging should inspect the TokenManager state directly.
 */
final readonly class MagicLinkStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private UserProviderInterface $provider,
        private TokenManagerInterface $tokenManager,
        private DateTimeFactoryInterface $dateTimeFactory,
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof VerifyPayload;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var VerifyPayload $payload */
        $token = $this->tokenManager->find($payload->token);

        if ($token === null) {
            return new AuthenticationResult(new InvalidToken());
        }

        if ($token->usedAt !== null) {
            return new AuthenticationResult(new InvalidToken());
        }

        if ($token->expiresAt <= $this->dateTimeFactory->now()) {
            return new AuthenticationResult(new InvalidToken());
        }

        if (!$this->tokenManager->consume($payload->token)) {
            return new AuthenticationResult(new InvalidToken());
        }

        $user = $this->provider->findById($token->userId);

        if ($user === null) {
            return new AuthenticationResult(new InvalidToken());
        }

        return new AuthenticationResult($user);
    }
}
