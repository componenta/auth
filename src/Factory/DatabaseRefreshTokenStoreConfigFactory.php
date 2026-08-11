<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStoreConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class DatabaseRefreshTokenStoreConfigFactory
{
    public function __invoke(
        ContainerInterface $container,
    ): DatabaseRefreshTokenStoreConfig {
        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $prefix = ConfigKey::AUTH
            . '.'
            . ConfigKey::JWT
            . '.'
            . ConfigKey::REFRESH_STORE;

        return new DatabaseRefreshTokenStoreConfig(
            tokenTable: $config->string(
                new ConfigPath($prefix . '.tokenTable'),
                'refresh_tokens',
            ),
            familyTable: $config->string(
                new ConfigPath($prefix . '.familyTable'),
                'refresh_token_families',
            ),
            tokenHashColumn: $config->string(
                new ConfigPath($prefix . '.columns.tokenHash'),
                'token_hash',
            ),
            familyIdColumn: $config->string(
                new ConfigPath($prefix . '.columns.familyId'),
                'family_id',
            ),
            subjectIdColumn: $config->string(
                new ConfigPath($prefix . '.columns.subjectId'),
                'user_id',
            ),
            expiresAtColumn: $config->string(
                new ConfigPath($prefix . '.columns.expiresAt'),
                'expires_at',
            ),
            consumedAtColumn: $config->string(
                new ConfigPath($prefix . '.columns.consumedAt'),
                'consumed_at',
            ),
            revokedAtColumn: $config->string(
                new ConfigPath($prefix . '.columns.revokedAt'),
                'revoked_at',
            ),
            compromisedAtColumn: $config->string(
                new ConfigPath($prefix . '.columns.compromisedAt'),
                'compromised_at',
            ),
            lockNonceColumn: $config->string(
                new ConfigPath($prefix . '.columns.lockNonce'),
                'lock_nonce',
            ),
        );
    }
}
