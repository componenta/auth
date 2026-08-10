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
    private readonly UserProviderInterface $provider;
    private readonly PasswordHasherInterface&PasswordVerifierInterface $hasher;
    private readonly string $dummyHash;

    public function __construct(
        UserProviderInterface $provider,
        PasswordHasherInterface&PasswordVerifierInterface $hasher = new PasswordHasher(),
        ?string $dummyHash = null,
    ) {
        $this->provider = $provider;
        $this->hasher = $hasher;
        // Compute during construction/warm-up, never on the first unknown user.
        $this->dummyHash = $dummyHash ?? $hasher->hash('componenta-auth-dummy-password');
    }

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof Payload;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var Payload $payload */
        $user = $this->provider->provide($payload);
        $valid = $this->hasher->verify($payload->password, $user?->hash ?? $this->dummyHash);

        return $user === null || !$valid
            ? new AuthenticationResult(new InvalidCredentials())
            : new AuthenticationResult($user);
    }
}
