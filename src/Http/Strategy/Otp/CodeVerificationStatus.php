<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

enum CodeVerificationStatus: string
{
    case Verified = 'verified';
    case Invalid = 'invalid';
    case Expired = 'expired';
    case TooManyAttempts = 'too_many_attempts';
}
