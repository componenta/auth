<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Support;

use Cycle\Database\Config\DatabaseConfig;
use Cycle\Database\Config\MySQL\DsnConnectionConfig;
use Cycle\Database\Config\MySQLDriverConfig;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseManager;

final class MySqlDatabaseFixture
{
    public static function available(): bool
    {
        return extension_loaded('pdo_mysql')
            && is_string(getenv('AUTH_TEST_MYSQL_DSN'))
            && getenv('AUTH_TEST_MYSQL_DSN') !== '';
    }

    public static function create(): DatabaseInterface
    {
        $dsn = getenv('AUTH_TEST_MYSQL_DSN');

        if (!is_string($dsn) || $dsn === '') {
            throw new \RuntimeException('AUTH_TEST_MYSQL_DSN is not configured.');
        }

        $user = getenv('AUTH_TEST_MYSQL_USER');
        $password = getenv('AUTH_TEST_MYSQL_PASSWORD');
        $user = is_string($user) && $user !== '' ? $user : null;
        $password = is_string($password) && $password !== '' ? $password : null;
        $manager = new DatabaseManager(new DatabaseConfig([
            'default' => 'default',
            'databases' => [
                'default' => ['connection' => 'mysql'],
            ],
            'connections' => [
                'mysql' => new MySQLDriverConfig(
                    connection: new DsnConnectionConfig(
                        dsn: $dsn,
                        user: $user,
                        password: $password,
                    ),
                    timezone: 'UTC',
                    queryCache: false,
                ),
            ],
        ]));

        return $manager->database('default');
    }
}
