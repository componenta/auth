<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Identity\IdentityInterface;

interface UserProviderInterface
{
    public function provide(Payload $payload): null|(IdentityInterface&PasswordAwareInterface);
}
