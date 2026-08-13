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
use Componenta\Identity\Uuid;
use Psr\Clock\ClockInterface;

final readonly class JwtStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private SignerInterface $signer,
        private JwtUserProviderInterface $provider,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof BearerPayload;
    }

    #[\Override]
    public function attempt(#[\SensitiveParameter] object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var BearerPayload $payload */
        $claims = $this->signer->parse($payload->token);

        if ($claims === null || !$this->matchesProfile($claims)) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $now = $this->clock->now()->getTimestamp();
        $skew = $this->config->clockSkew;

        if ($claims->expiresAt <= $now - $skew) {
            return new AuthenticationResult(new AccessTokenExpired());
        }

        if (
            $claims->issuedAt > $now + $skew
            || ($claims->notBefore !== null && $claims->notBefore > $now + $skew)
            || $claims->expiresAt <= $claims->issuedAt
            || $claims->expiresAt - $claims->issuedAt > $this->config->accessTtl
        ) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        try {
            $subjectId = Uuid::fromString($claims->subject);
        } catch (\InvalidArgumentException) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $identity = $this->provider->findByUuid($subjectId);

        return $identity === null || !$subjectId->equals($identity->uuid)
            ? new AuthenticationResult(new InvalidAccessToken())
            : new AuthenticationResult($identity);
    }

    private function matchesProfile(Claims $claims): bool
    {
        return $claims->issuer === $this->config->issuer
            && $claims->audience === $this->config->audience
            && $claims->type === $this->config->type;
    }
}
