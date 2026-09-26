<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidInterface;

/**
 * Resolves an authentication subject by its canonical UUID.
 *
 * Mechanisms that authenticate by another identifier keep their own resolver
 * contracts until they have established the canonical subject UUID.
 */
interface IdentityProviderInterface
{
    public function findByUuid(UuidInterface $uuid): ?IdentityInterface;
}
