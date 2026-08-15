<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

enum PasswordResetResult
{
    case Success;
    case InvalidToken;
    case PasswordRejected;
}
