<?php

declare(strict_types=1);

namespace Componenta\Auth;

final class ConfigKey extends \Componenta\Config\ConfigKey
{
    public const string AUTH = 'auth';
    public const string SESSION = 'session';
    public const string REMEMBER_ME = 'rememberMe';
    public const string COOKIE = 'cookie';
    public const string STRATEGIES = 'strategies';
    public const string MAGIC_LINK = 'magicLink';
    public const string DENIED = 'denied';
    public const string JWT = 'jwt';
    public const string PASSWORD_RESET = 'passwordReset';
    public const string LISTENERS = 'Componenta\Auth\Event::listeners';
}
