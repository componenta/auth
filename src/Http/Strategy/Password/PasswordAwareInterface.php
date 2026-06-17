<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

interface PasswordAwareInterface
{
    public string $hash { get; }
}