<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStoreConfig;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;

final readonly class DatabaseCodeStoreConfigFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): DatabaseCodeStoreConfig {
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
            . ConfigKey::OTP
            . '.'
            . ConfigKey::STORE;

        return new DatabaseCodeStoreConfig(
            table: $config->string(new ConfigPath($prefix . '.table'), 'otp_codes'),
            destinationColumn: $config->string(new ConfigPath($prefix . '.columns.destination'), 'destination'),
            subjectIdColumn: $config->string(new ConfigPath($prefix . '.columns.subjectId'), 'user_id'),
            challengeIdColumn: $config->string(new ConfigPath($prefix . '.columns.challengeId'), 'challenge_id'),
            verifierColumn: $config->string(new ConfigPath($prefix . '.columns.verifier'), 'verifier'),
            expiresAtColumn: $config->string(new ConfigPath($prefix . '.columns.expiresAt'), 'expires_at'),
            attemptsColumn: $config->string(new ConfigPath($prefix . '.columns.attempts'), 'attempts'),
        );
    }
}
