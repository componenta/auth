<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\EventListenerProviderInterface;
use Componenta\Auth\Factory\DatabaseRememberMeTokenManagerConfigFactory;
use Componenta\Auth\Factory\DatabaseRememberMeTokenManagerFactory;
use Componenta\Auth\Factory\DatabaseSessionManagerConfigFactory;
use Componenta\Auth\Factory\DatabaseSessionManagerFactory;
use Componenta\Auth\Factory\DeniedResponseFactoryFactory;
use Componenta\Auth\Factory\EventDispatcherFactory;
use Componenta\Auth\Factory\JwtConfigFactory;
use Componenta\Auth\Factory\JwtMagicLinkTokenHandlerFactory;
use Componenta\Auth\Factory\JwtOtpTokenHandlerFactory;
use Componenta\Auth\Factory\JwtPasswordTokenHandlerFactory;
use Componenta\Auth\Factory\LoginHandlerFactory;
use Componenta\Auth\Factory\LogoutHandlerFactory;
use Componenta\Auth\Factory\MagicLinkRequestHandlerFactory;
use Componenta\Auth\Factory\MagicLinkVerifyHandlerFactory;
use Componenta\Auth\Factory\OtpRequestHandlerFactory;
use Componenta\Auth\Factory\OtpVerifyHandlerFactory;
use Componenta\Auth\Factory\PriorityListenerProviderFactory;
use Componenta\Auth\Factory\RefreshHandlerFactory;
use Componenta\Auth\Factory\RefreshTokenManagerFactory;
use Componenta\Auth\Factory\RememberMeRegenerationListenerFactory;
use Componenta\Auth\Factory\RememberMeTerminationListenerFactory;
use Componenta\Auth\Factory\RevokeHandlerFactory;
use Componenta\Auth\Factory\TokenPairResponseFactory;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Handler\LogoutHandler;
use Componenta\Auth\Http\Strategy\Jwt\JwtConfig;
use Componenta\Auth\Http\Strategy\Jwt\MagicLink\TokenHandler as JwtMagicLinkTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Otp\TokenHandler as JwtOtpTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\Password\TokenHandler as JwtPasswordTokenHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshHandler;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Http\Strategy\Jwt\RefreshTokenManager;
use Componenta\Auth\Http\Strategy\Jwt\RevokeHandler;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\RequestHandler as MagicLinkRequestHandler;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler as MagicLinkVerifyHandler;
use Componenta\Auth\Http\Strategy\Otp\RequestHandler as OtpRequestHandler;
use Componenta\Auth\Http\Strategy\Otp\VerifyHandler as OtpVerifyHandler;
use Componenta\Auth\Http\Strategy\Password\LoginHandler;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManagerConfig;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\DatabaseSessionManagerConfig;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionIdGenerator;
use Componenta\Auth\Session\SessionIdGeneratorInterface;
use Componenta\Auth\Session\SessionManagerInterface;

class ConfigProvider extends \Componenta\Config\ConfigProvider
{
    protected function getFactories(): array
    {
        return [
            EventDispatcher::class => EventDispatcherFactory::class,
            EventListenerProviderInterface::class => PriorityListenerProviderFactory::class,
            DatabaseSessionManagerConfig::class => DatabaseSessionManagerConfigFactory::class,
            SessionManagerInterface::class => DatabaseSessionManagerFactory::class,
            DatabaseRememberMeTokenManagerConfig::class => DatabaseRememberMeTokenManagerConfigFactory::class,
            RememberMeTokenManagerInterface::class => DatabaseRememberMeTokenManagerFactory::class,
            DeniedResponseFactoryInterface::class => DeniedResponseFactoryFactory::class,
            LoginHandler::class => LoginHandlerFactory::class,
            MagicLinkVerifyHandler::class => MagicLinkVerifyHandlerFactory::class,
            MagicLinkRequestHandler::class => MagicLinkRequestHandlerFactory::class,
            OtpVerifyHandler::class => OtpVerifyHandlerFactory::class,
            OtpRequestHandler::class => OtpRequestHandlerFactory::class,
            LogoutHandler::class => LogoutHandlerFactory::class,
            JwtConfig::class => JwtConfigFactory::class,
            RefreshTokenManager::class => RefreshTokenManagerFactory::class,
            TokenPairResponse::class => TokenPairResponseFactory::class,
            JwtPasswordTokenHandler::class => JwtPasswordTokenHandlerFactory::class,
            JwtMagicLinkTokenHandler::class => JwtMagicLinkTokenHandlerFactory::class,
            JwtOtpTokenHandler::class => JwtOtpTokenHandlerFactory::class,
            RefreshHandler::class => RefreshHandlerFactory::class,
            RevokeHandler::class => RevokeHandlerFactory::class,
            RememberMe\RememberMeTerminationListener::class => RememberMeTerminationListenerFactory::class,
            RememberMe\RememberMeRegenerationListener::class => RememberMeRegenerationListenerFactory::class,
        ];
    }

    protected function getInvokables(): array
    {
        return [
            SessionIdGeneratorInterface::class => SessionIdGenerator::class,
            SessionAttributeExtractorInterface::class => SessionAttributeExtractor::class,
            RefreshTokenGenerator::class,
        ];
    }

    protected function getConfig(): array
    {
        return [
            ConfigKey::AUTH => [
                ConfigKey::SESSION => [
                    'table' => 'sessions',
                    'dateFormat' => 'Y-m-d H:i:s',
                    'lazyLoad' => true,
                    'idleTimeout' => 1800,
                    'absoluteTimeout' => 28800,
                    'regenerationInterval' => 300,
                    'regenerationGracePeriod' => 30,
                    'columns' => [
                        'id' => 'id',
                        'userId' => 'user_id',
                        'ip' => 'ip',
                        'userAgent' => 'user_agent',
                        'expiresAt' => 'expires_at',
                        'absoluteExpiresAt' => 'absolute_expires_at',
                        'regenerateAt' => 'regenerate_at',
                        'replacedBy' => 'replaced_by',
                        'createdAt' => 'created_at',
                        'lastActiveAt' => 'last_active_at',
                        'attributes' => 'attributes',
                    ],
                ],
                ConfigKey::REMEMBER_ME => [
                    'table' => 'remember_me_tokens',
                    'dateFormat' => 'Y-m-d H:i:s',
                    'ttl' => 2592000,
                    'cookieName' => 'rmid',
                    'columns' => [
                        'id' => 'id',
                        'userId' => 'user_id',
                        'sessionId' => 'session_id',
                        'token' => 'token',
                        'expiresAt' => 'expires_at',
                        'createdAt' => 'created_at',
                    ],
                ],
                ConfigKey::DENIED => [
                    'defaultStatus' => 401,
                    'statusMap' => [
                        'unauthorized' => 401,
                        'invalid_credentials' => 401,
                        'invalid_token' => 401,
                        'token_expired' => 401,
                        'token_already_used' => 401,
                        'user_disabled' => 403,
                        'invalid_code' => 401,
                        'code_expired' => 401,
                        'too_many_attempts' => 429,
                        'rate_limited' => 429,
                        'invalid_access_token' => 401,
                        'access_token_expired' => 401,
                        'invalid_refresh_token' => 401,
                        'refresh_token_expired' => 401,
                        'token_family_compromised' => 401,
                    ],
                ],
                ConfigKey::JWT => [
                    'accessTtl' => 900,
                    'refreshTtl' => 604800,
                    'issuer' => '',
                    'audience' => '',
                ],
            ],
        ];
    }
}
