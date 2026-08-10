<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

enum PasswordResetResult: string
{
    case Success = 'success';
    case InvalidToken = 'invalid_token';
}
