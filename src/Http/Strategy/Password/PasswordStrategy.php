<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Stdlib\PasswordHasher;
use Componenta\Stdlib\PasswordHasherInterface;
use Componenta\Stdlib\PasswordVerifierInterface;

final class PasswordStrategy implements AuthenticationStrategyInterface
{
    /**
     * Dummy hash used to equalize verify() time for unknown users.
     * Lazily initialized on first need to avoid paying the cost on boot.
     */
    private ?string $dummyHash = null;

    public function __construct(
        private readonly UserProviderInterface $provider,
        private readonly PasswordHasherInterface&PasswordVerifierInterface $hasher = new PasswordHasher(),
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof Payload;
    }

    /**
     * @throws \Throwable
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var Payload $payload */
        $user = $this->provider->provide($payload);

        // Always run verify() to prevent timing-based user enumeration.
        // For unknown users, compare against a dummy hash so total wall-clock
        // time of the branch stays close to the valid-user branch.
        $hash = $user?->hash ?? $this->dummyHash();
        $valid = $this->hasher->verify($payload->password, $hash);

        if ($user === null || !$valid) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        return new AuthenticationResult($user);
    }

    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->hash('');
    }
}
