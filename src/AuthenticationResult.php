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
    ) {
        if ($this->session === null) {
            return;
        }

        if (!$this->subject instanceof IdentityInterface) {
            throw new \InvalidArgumentException(
                'A denied authentication result cannot contain a session.',
            );
        }

        if (!$this->session->subjectId->equals($this->subject->uuid)) {
            throw new \InvalidArgumentException(
                'The authenticated session must belong to the returned identity.',
            );
        }
    }
}
