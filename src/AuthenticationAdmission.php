<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidInterface;

/**
 * Final, uncached admission decision before issuing or strengthening credentials.
 * Bind one application admission service to every issuer, regardless of mechanism.
 * Infrastructure failures propagate; a missing policy is never an implicit allow.
 */
final readonly class AuthenticationAdmission
{
    public function __construct(
        private IdentityProviderInterface $identities,
        private AuthenticationGuardInterface $guard,
    ) {}

    public function check(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
    ): IdentityInterface|DeniedReasonInterface {
        $identity = $this->identities->findByUuid($subjectId);

        if ($identity === null || !$identity->uuid->equals($subjectId)) {
            return new InvalidCredentials();
        }

        return $this->guard->check($identity, $evidence) ?? $identity;
    }
}
