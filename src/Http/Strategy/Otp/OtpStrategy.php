<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\Strategy\Otp\Denied\InvalidCode;
use Componenta\Auth\Http\Strategy\Otp\Denied\TooManyAttempts;
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

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof OtpPayload;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var OtpPayload $payload */
        $result = $this->store->verifyAndConsume(
            destination: $payload->destination,
            presentedCode: $payload->code,
            now: $this->clock->now()->getTimestamp(),
            maxAttempts: $this->config->maxAttempts,
        );

        if ($result->status === CodeVerificationStatus::TooManyAttempts) {
            return new AuthenticationResult(new TooManyAttempts());
        }

        if ($result->status !== CodeVerificationStatus::Verified || $result->userId === null) {
            return new AuthenticationResult(new InvalidCode());
        }

        $user = $this->provider->findById($result->userId);

        return $user === null
            ? new AuthenticationResult(new InvalidCode())
            : new AuthenticationResult($user);
    }
}
