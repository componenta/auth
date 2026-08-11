<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Support;

use Cycle\Database\Config\DatabaseConfig;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseManager;

final class SqliteDatabaseFixture
{
    public static function create(): DatabaseInterface
    {
        return (new DatabaseManager(new DatabaseConfig([
            'databases' => [
                'default' => ['connection' => 'sqlite'],
            ],
            'connections' => [
                'sqlite' => new SQLiteDriverConfig(),
            ],
        ])))->database('default');
    }
}
