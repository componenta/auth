<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Session;

use Componenta\Identity\IdentityInterface;

interface UserProviderInterface
{
    /** Resolves the canonical UUID string stored in a session. */
    public function findById(int|string $userId): ?IdentityInterface;
}
