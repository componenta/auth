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
    private readonly string $dummyHash;

    public function __construct(
        private readonly UserProviderInterface $provider,
        private readonly PasswordHasherInterface&PasswordVerifierInterface $hasher = new PasswordHasher(),
        ?string $dummyHash = null,
    ) {
        $this->dummyHash = $dummyHash
            ?? $this->hasher->hash('componenta-auth-dummy-password');
    }

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof Payload;
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var Payload $payload */
        $identity = $this->provider->findByIdentity($payload->identity);
        $valid = $this->hasher->verify(
            $payload->password,
            $identity->hash ?? $this->dummyHash,
        );

        return $identity === null || !$valid
            ? new AuthenticationResult(new InvalidCredentials())
            : new AuthenticationResult($identity);
    }
}
