<?php

declare(strict_types=1);

namespace Componenta\Auth;

interface AuthSubjectInterface
{
    public function getAuthSubjectId(): int|string;
}
