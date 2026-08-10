<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

/**
 * Result of an authentication attempt.
 *
 * In addition to a response transport payload, a strategy may expose verified
 * request-scoped state (for example the resolved SessionInterface) so later
 * middleware does not repeat security-sensitive lookups.
 */
final readonly class AuthenticationResult
{
    /**
     * @param array<string, mixed> $attributes Verified request-scoped state
     */
    public function __construct(
        public IdentityInterface|DeniedReasonInterface $subject,
        public ?object $transportPayload = null,
        public array $attributes = [],
    ) {}
}
