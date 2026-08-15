<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidInterface;

interface JwtUserProviderInterface
{
    public function findByUuid(UuidInterface $uuid): ?IdentityInterface;
}
