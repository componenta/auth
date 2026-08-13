<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\Strategy\Otp\Denied\InvalidCode;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

final readonly class OtpStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private UserProviderInterface $provider,
        private CodeStoreInterface $store,
        private OtpConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof OtpPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        ContextInterface $context,
    ): AuthenticationResult {
        /** @var OtpPayload $payload */
        $result = $this->store->verifyAndConsume(
            destination: $payload->destination,
            presentedCode: $payload->code,
            now: $this->clock->now()->getTimestamp(),
            maxAttempts: $this->config->maxAttempts,
        );

        // Public verification deliberately collapses every negative store state.
        // Exposing Expired/TooManyAttempts would let an attacker distinguish a
        // destination for which a worker created a challenge from one for which
        // no account exists. Operational detail remains inside the store/rate limiter.
        if (
            $result->status !== CodeVerificationStatus::Verified
            || $result->subjectId === null
        ) {
            return new AuthenticationResult(new InvalidCode());
        }

        $identity = $this->provider->findByUuid($result->subjectId);

        return $identity === null || !$result->subjectId->equals($identity->uuid)
            ? new AuthenticationResult(new InvalidCode())
            : new AuthenticationResult($identity);
    }
}
