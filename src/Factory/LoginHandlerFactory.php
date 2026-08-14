<?php

declare(strict_types=1);

namespace Componenta\Auth\Factory;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\ConfigKey;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Strategy\Password\LoginHandler;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Config\Config;
use Componenta\Config\ConfigPath;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final readonly class LoginHandlerFactory
{
    public function __invoke(
        #[\SensitiveParameter]
        ContainerInterface $container,
    ): LoginHandler {
        /** @var PasswordExtractor $extractor */
        $extractor = $container->get(PasswordExtractor::class);
        /** @var AuthenticatorInterface $authenticator */
        $authenticator = $container->get(AuthenticatorInterface::class);
        /** @var SessionManagerInterface $sessionManager */
        $sessionManager = $container->get(SessionManagerInterface::class);
        /** @var PayloadStorageInterface $storage */
        $storage = $container->get(PayloadStorageInterface::class);
        /** @var DeniedResponseFactoryInterface $deniedResponseFactory */
        $deniedResponseFactory = $container->get(DeniedResponseFactoryInterface::class);
        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);
        /** @var SessionAttributeExtractorInterface $attributeExtractor */
        $attributeExtractor = $container->get(SessionAttributeExtractorInterface::class);

        $config = $container->get(ConfigKey::CONFIG);

        if (!$config instanceof Config) {
            throw new \LogicException(sprintf(
                '%s must resolve to %s.',
                ConfigKey::CONFIG,
                Config::class,
            ));
        }

        $tokenManager = null;
        $rememberMeEnabled = $config->bool(new ConfigPath(
            ConfigKey::AUTH . '.' . ConfigKey::REMEMBER_ME . '.' . ConfigKey::ENABLED,
        ), false);

        if ($rememberMeEnabled) {
            if (!$container->has(RememberMeTokenManagerInterface::class)) {
                throw new \LogicException(sprintf(
                    'Remember-me is enabled, but %s is not registered.',
                    RememberMeTokenManagerInterface::class,
                ));
            }

            $candidate = $container->get(RememberMeTokenManagerInterface::class);

            if (!$candidate instanceof RememberMeTokenManagerInterface) {
                throw new \LogicException(sprintf(
                    '%s must resolve to %s.',
                    RememberMeTokenManagerInterface::class,
                    RememberMeTokenManagerInterface::class,
                ));
            }

            $tokenManager = $candidate;
        }

        return new LoginHandler(
            $extractor,
            $authenticator,
            $sessionManager,
            $storage,
            $deniedResponseFactory,
            $responseFactory,
            $tokenManager,
            $attributeExtractor,
        );
    }
}
