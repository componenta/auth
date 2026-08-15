<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

enum RefreshTokenRotationStatus: string
{
    case Rotated = 'rotated';
    case Invalid = 'invalid';
    case Expired = 'expired';
    case Reused = 'reused';
}
