<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Session;

use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidInterface;

interface UserProviderInterface
{
    public function findByUuid(UuidInterface $uuid): ?IdentityInterface;
}
