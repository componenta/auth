<?php

declare(strict_types=1);

namespace Componenta\Auth;

final class ConfigKey extends \Componenta\Config\ConfigKey
{
    public const string AUTH = 'auth';
    public const string SESSION = 'session';
    public const string REMEMBER_ME = 'rememberMe';
    public const string STRATEGIES = 'strategies';
    public const string EVENTS = 'events';
    public const string ENABLED = 'enabled';
    public const string DENIED = 'denied';
    public const string JWT = 'jwt';
    public const string OTP = 'otp';
    public const string STORE = 'store';
    public const string REFRESH_STORE = 'refreshStore';
    public const string HMAC_KEY = 'hmacKey';
    public const string LISTENERS = 'Componenta\\Auth\\Event::listeners';
}
