<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

/**
 * Applies fail-closed subject guards to successful authentication results.
 *
 * Concrete mechanisms remain responsible for avoiding irreversible credential
 * strengthening before this boundary. HTTP publication rollback continues to
 * use CredentialTransportState in componenta/auth-http.
 */
final readonly class GuardedAuthenticator implements AuthenticatorInterface
{
    /** @var list<AuthenticationGuardInterface> */
    private array $guards;

    public function __construct(
        private AuthenticatorInterface $authenticator,
        AuthenticationGuardInterface ...$guards,
    ) {
        $this->guards = array_values($guards);
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        $result = $this->authenticator->attempt($payload, $context);

        if (!$result->subject instanceof IdentityInterface) {
            return $result;
        }

        $evidence = $result->evidence
            ?? throw new \LogicException(
                'A successful authentication result must contain authentication evidence.',
            );

        foreach ($this->guards as $guard) {
            $denial = $guard->check($result->subject, $evidence);

            if ($denial !== null) {
                return new AuthenticationResult($denial);
            }
        }

        return $result;
    }
}
