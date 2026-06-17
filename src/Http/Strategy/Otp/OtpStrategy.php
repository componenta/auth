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

/**
 * Authenticates a user via a one-time code.
 *
 * Handles the verify step of the OTP flow:
 * looks up stored code by destination, validates expiry,
 * checks attempt limit, compares code, loads user.
 *
 * The code is invalidated after successful verification or when the
 * attempt limit is reached. Negative outcomes other than rate-limit
 * collapse to {@see InvalidCode} to prevent code-state enumeration.
 * {@see TooManyAttempts} is preserved - it is a legitimate rate-limit
 * signal for the client (HTTP 429), tied to destination, not to code state.
 */
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

    /**
     * Must only be called after {@see supports()} returns true.
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var OtpPayload $payload */
        $stored = $this->store->find($payload->destination);

        if ($stored === null) {
            return new AuthenticationResult(new InvalidCode());
        }

        if ($stored->expiresAt <= $this->now()) {
            $this->store->invalidate($payload->destination);

            return new AuthenticationResult(new InvalidCode());
        }

        // Increment attempts BEFORE the comparison. This closes the parallel
        // brute-force window: N concurrent requests with guesses would all
        // pass the stale `$stored->attempts` check otherwise. Here each
        // request gets a unique post-increment count, and only the first
        // maxAttempts requests continue to hash_equals.
        $newAttempts = $this->store->incrementAttempts($payload->destination);

        if ($newAttempts > $this->config->maxAttempts) {
            $this->store->invalidate($payload->destination);

            return new AuthenticationResult(new TooManyAttempts());
        }

        if (!hash_equals($stored->code, $payload->code)) {
            return new AuthenticationResult(new InvalidCode());
        }

        // Code matches - atomically consume to prevent replay.
        // A concurrent request with the same code will get null here.
        $consumed = $this->store->consume($payload->destination);

        if ($consumed === null) {
            return new AuthenticationResult(new InvalidCode());
        }

        // Re-check expiry on the consumed (authoritative) data to close
        // the TOCTOU gap between find() and consume().
        if ($consumed->expiresAt <= $this->now()) {
            return new AuthenticationResult(new InvalidCode());
        }

        $user = $this->provider->findById($consumed->userId);

        if ($user === null) {
            return new AuthenticationResult(new InvalidCode());
        }

        return new AuthenticationResult($user);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
