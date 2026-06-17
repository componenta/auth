<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

/**
 * Payload that supports "remember me" functionality.
 *
 * When implemented by a login payload, the authentication system
 * can create a persistent remember-me token for automatic re-login.
 */
interface RememberMeAwareInterface
{
    public bool $remember { get; }
}
