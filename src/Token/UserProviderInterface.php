<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidInterface;

/** Resolves identities for request and consume phases of one-time flows. */
interface UserProviderInterface
{
    public function findByIdentity(string $identity): ?IdentityInterface;

    public function findByUuid(UuidInterface $uuid): ?IdentityInterface;
}
