<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

final readonly class AuthSubject
{
    public static function id(IdentityInterface $identity): int|string
    {
        return $identity instanceof AuthSubjectInterface
            ? $identity->getAuthSubjectId()
            : $identity->uuid->toString();
    }
}
