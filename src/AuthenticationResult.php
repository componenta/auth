<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Session\SessionInterface;
use Componenta\Identity\IdentityInterface;

final readonly class AuthenticationResult
{
    public function __construct(
        public IdentityInterface|DeniedReasonInterface $subject,
        public ?object $transportPayload = null,
        public ?SessionInterface $session = null,
    ) {}
}
