<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\Http\Strategy\Jwt\Denied\AccessTokenExpired;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidAccessToken;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

/**
 * Authenticates a user via JWT access token.
 *
 * Accepts BearerPayload from BearerExtractor, parses
 * and verifies the JWT, checks expiry, and resolves the user.
 */
final readonly class JwtStrategy implements AuthenticationStrategyInterface
{
    /**
     * @param JwtConfig|null $config When provided with non-empty issuer/audience,
     *                               tokens with mismatching iss/aud are rejected.
     *                               nbf is always enforced when present in the token.
     */
    public function __construct(
        private SignerInterface $signer,
        private JwtUserProviderInterface $provider,
        private ClockInterface $clock = new Clock(),
        private ?JwtConfig $config = null,
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof BearerPayload;
    }

    /**
     * Must only be called after {@see supports()} returns true.
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var BearerPayload $payload */
        $claims = $this->signer->parse($payload->token);

        if ($claims === null) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $now = $this->now();

        if ($claims->expiresAt <= $now) {
            return new AuthenticationResult(new AccessTokenExpired());
        }

        if ($claims->notBefore !== null && $claims->notBefore > $now) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        if (!$this->claimsMatchExpectations($claims)) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $user = $this->provider->findById($claims->subject);

        if ($user === null) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        return new AuthenticationResult($user);
    }

    private function claimsMatchExpectations(Claims $claims): bool
    {
        if ($this->config === null) {
            return true;
        }

        if ($this->config->issuer !== '' && $claims->issuer !== $this->config->issuer) {
            return false;
        }

        if ($this->config->audience !== '' && $claims->audience !== $this->config->audience) {
            return false;
        }

        return true;
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
