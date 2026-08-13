<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests;

use Componenta\Auth\Event\EventDispatcher;
use Componenta\Auth\Event\PriorityListenerProvider;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenHousekeeper;
use Componenta\Auth\Http\Strategy\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Http\Strategy\Jwt\RefreshToken;
use Componenta\Auth\Http\Strategy\Otp\DatabaseCodeStore;
use Componenta\Auth\Http\Strategy\Otp\StoredCode;
use Componenta\Auth\RememberMe\DatabaseRememberMeTokenManager;
use Componenta\Auth\Session\DatabaseSessionManager;
use Componenta\Auth\Session\SessionIdGeneratorInterface;
use Componenta\Auth\Tests\Support\MySqlDatabaseFixture;
use Componenta\Auth\Token\TokenConfig;
use Componenta\Auth\Token\TokenManager;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class DatabaseMySql84SchemaContractTest extends TestCase
{
    private const string OTP_HMAC_KEY =
        'componenta-auth-schema-contract-key-32-bytes';

    public function testReferenceSchemaSupportsBuiltInCredentialStores(): void
    {
        if (!MySqlDatabaseFixture::available()) {
            self::markTestSkipped(
                'AUTH_TEST_MYSQL_DSN and pdo_mysql are required for MySQL schema tests.',
            );
        }

        $database = MySqlDatabaseFixture::create();
        self::resetSchema($database);
        self::installReferenceSchema($database);
        $subjectId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $clock = new FrozenClock(1000, 'UTC');

        $sessions = new DatabaseSessionManager(
            $database,
            new SchemaSessionIdGenerator('CaseSession', 'casesession'),
            $clock,
            new EventDispatcher(new PriorityListenerProvider()),
        );
        $first = $sessions->create($subjectId, [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'schema-contract',
        ]);
        $second = $sessions->create($subjectId, [
            DatabaseSessionManager::ATTR_IP => '127.0.0.1',
            DatabaseSessionManager::ATTR_USER_AGENT => 'schema-contract',
        ]);
        self::assertNotSame($first->id, $second->id);
        self::assertSame(2, $database->select()->from('sessions')->count());

        $remember = new DatabaseRememberMeTokenManager($database, $clock);
        self::assertNotSame('', $remember->create($subjectId, $first->id));

        $otp = new DatabaseCodeStore($database, self::OTP_HMAC_KEY);
        $otp->store(new StoredCode(
            $subjectId,
            '123456',
            'CaseSensitive@example.com',
            900,
        ));
        $otp->store(new StoredCode(
            $subjectId,
            '654321',
            'casesensitive@example.com',
            2000,
        ));
        self::assertSame(1, $otp->cleanup(1000, 10));
        self::assertSame(1, $database->select()->from('otp_codes')->count());

        $tokens = new TokenManager(
            $database,
            $clock,
            new TokenConfig('magic_link_tokens', 'magic_link'),
        );
        $plainToken = $tokens->replaceForSubject($subjectId);
        self::assertTrue($tokens->consume($plainToken));
        self::assertSame(1, $tokens->cleanup(10));

        $refresh = new DatabaseRefreshTokenStore($database);
        $refresh->storeInitial(new RefreshToken(
            str_repeat('a', 64),
            $subjectId,
            str_repeat('b', 128),
            900,
        ));
        self::assertSame(
            1,
            (new DatabaseRefreshTokenHousekeeper($database))->cleanup(1000, 10),
        );
    }

    private static function installReferenceSchema(DatabaseInterface $database): void
    {
        $path = dirname(__DIR__) . '/resources/schema/mysql-8.4.sql';
        $sql = file_get_contents($path);

        if (!is_string($sql) || $sql === '') {
            throw new \RuntimeException('Unable to read the MySQL reference schema.');
        }

        $statements = preg_split('/;\s*(?=CREATE TABLE|\z)/', trim($sql));

        if (!is_array($statements)) {
            throw new \RuntimeException('Unable to parse the MySQL reference schema.');
        }

        foreach ($statements as $statement) {
            $statement = trim($statement);
            if ($statement !== '') {
                $database->execute($statement);
            }
        }
    }

    private static function resetSchema(DatabaseInterface $database): void
    {
        $database->execute('SET FOREIGN_KEY_CHECKS = 0');
        foreach ([
            'refresh_tokens',
            'refresh_token_families',
            'password_reset_tokens',
            'magic_link_tokens',
            'otp_codes',
            'remember_me_tokens',
            'sessions',
        ] as $table) {
            $database->execute('DROP TABLE IF EXISTS ' . $table);
        }
        $database->execute('SET FOREIGN_KEY_CHECKS = 1');
    }
}

final class SchemaSessionIdGenerator implements SessionIdGeneratorInterface
{
    /** @var list<string> */
    private array $ids;

    public function __construct(string ...$ids)
    {
        $this->ids = array_values($ids);
    }

    public function generate(): string
    {
        return array_shift($this->ids)
            ?? throw new \LogicException('No schema-test session ID remains.');
    }
}
