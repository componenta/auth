<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

/**
 * Result of an authentication attempt.
 *
 * Wraps the authenticated identity (or denial reason) and an optional
 * transport payload that should be stored via PayloadStorageInterface.
 */
final readonly class AuthenticationResult
{
    public function __construct(
        public IdentityInterface|DeniedReasonInterface $subject,
        public ?object $transportPayload = null,
    ) {}
}
