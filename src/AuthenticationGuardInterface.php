<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

/**
 * Decides whether a successfully proven identity may authenticate.
 *
 * Guards are not authorization policies. They reject subjects that must not
 * establish or continue authentication, for example disabled/deleted users.
 */
interface AuthenticationGuardInterface
{
    public function check(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): ?DeniedReasonInterface;
}
