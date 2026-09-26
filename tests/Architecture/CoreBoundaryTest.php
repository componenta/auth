<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Architecture;

use PHPUnit\Framework\TestCase;

final class CoreBoundaryTest extends TestCase
{
    public function testComposerDoesNotPullConcreteAuthenticationCapabilities(): void
    {
        $composer = json_decode(
            file_get_contents(dirname(__DIR__, 2) . '/composer.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        self::assertIsArray($composer);

        $requires = array_keys($composer['require'] ?? []);

        foreach ([
            'componenta/config',
            'componenta/di',
            'componenta/password',
            'cycle/database',
            'lcobucci/jwt',
            'psr/container',
            'psr/http-factory',
            'psr/http-message',
            'psr/http-server-handler',
            'psr/http-server-middleware',
        ] as $forbidden) {
            self::assertNotContains(
                $forbidden,
                $requires,
                sprintf('Auth 3 core must not require %s.', $forbidden),
            );
        }
    }

    public function testConcreteCapabilityNamespacesAreNotPartOfCore(): void
    {
        $source = dirname(__DIR__, 2) . '/src';

        foreach ([
            'Factory',
            'Http',
            'PasswordReset',
            'RememberMe',
            'Session',
            'Token',
        ] as $directory) {
            self::assertDirectoryDoesNotExist(
                $source . '/' . $directory,
                sprintf('%s belongs to a dedicated Auth 3 package.', $directory),
            );
        }

        self::assertFileDoesNotExist($source . '/ConfigProvider.php');
        self::assertFileDoesNotExist($source . '/ConfigKey.php');
    }
}
