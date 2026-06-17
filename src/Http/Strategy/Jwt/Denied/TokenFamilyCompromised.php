<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

/**
 * A revoked refresh token was reused, indicating potential theft.
 *
 * The entire token family has been revoked as a precaution.
 * The user must re-authenticate.
 */
final class TokenFamilyCompromised implements DeniedReasonInterface
{
    public string $code {
        get => 'token_family_compromised';
    }

    public function __construct(
        public readonly array $attributes = [],
    ) {}
}
