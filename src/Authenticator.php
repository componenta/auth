<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Exception\AuthenticationExceptionInterface;
use Componenta\Auth\Exception\NoStrategyFoundException;
use Componenta\Identity\IdentityInterface;

/**
 * Default authenticator implementation.
 *
 * Iterates through registered strategies. On success, returns immediately.
 * On failure, tries the next supporting strategy (chain on failure).
 */
final readonly class Authenticator implements AuthenticatorInterface
{
    /** @var AuthenticationStrategyInterface[] */
    private array $strategies;

    public function __construct(AuthenticationStrategyInterface ...$strategies)
    {
        $this->strategies = $strategies;
    }

    /**
     * @throws NoStrategyFoundException If no strategy supports the payload
     * @throws AuthenticationExceptionInterface
     */
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        $lastResult = null;

        foreach ($this->strategies as $strategy) {
            if ($strategy->supports($payload, $context)) {
                $result = $strategy->attempt($payload, $context);

                if ($result->subject instanceof IdentityInterface) {
                    return $result;
                }

                $lastResult = $result;
            }
        }

        return $lastResult ?? throw new NoStrategyFoundException($payload);
    }
}
