<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\MagicLink;

use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyHandler;
use PHPUnit\Framework\TestCase;

final class VerifyHandlerStorageContractTest extends TestCase
{
    public function testPublicHandlerRequiresReplacingCredentialStorage(): void
    {
        $constructor = (new \ReflectionClass(VerifyHandler::class))->getConstructor();
        self::assertNotNull($constructor);
        $parameters = $constructor->getParameters();
        $type = $parameters[3]->getType();

        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame(ReplacingPayloadStorage::class, $type->getName());
    }
}
