<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\Http\Strategy\Password;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\Strategy\Password\PasswordExtractor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class PasswordExtractorTest extends TestCase
{
    #[DataProvider('falseValues')]
    public function testStrictFalseValuesDoNotEnableRememberMe(mixed $value): void
    {
        $request = $this->request([
            'email' => 'User@Example.com',
            'password' => 'secret',
            'remember' => $value,
        ]);
        $payload = (new PasswordExtractor())->extract($request);

        self::assertSame('User@Example.com', $payload->identity);
        self::assertFalse($payload->remember);
    }

    /** @return iterable<array{mixed}> */
    public static function falseValues(): iterable
    {
        yield [false];
        yield [0];
        yield ['0'];
        yield ['false'];
        yield ['off'];
        yield ['no'];
        yield [''];
    }

    public function testWhitespacePaddedIdentityIsRejectedInsteadOfSilentlyNormalized(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new PasswordExtractor())->extract($this->request([
            'email' => ' User@Example.com ',
            'password' => 'secret',
        ]));
    }

    public function testArrayCredentialIsRejectedBeforeStringOperations(): void
    {
        $this->expectException(InvalidPayloadException::class);
        (new PasswordExtractor())->extract($this->request([
            'email' => ['not-a-string'],
            'password' => 'secret',
        ]));
    }

    public function testControlCharacterInIdentityIsRejectedAsInvalidPayload(): void
    {
        $this->expectException(InvalidPayloadException::class);

        (new PasswordExtractor())->extract($this->request([
            'email' => "user\n@example.com",
            'password' => 'secret',
        ]));
    }

    public function testUnknownBooleanRepresentationIsRejected(): void
    {
        $this->expectException(InvalidPayloadException::class);
        (new PasswordExtractor())->extract($this->request([
            'email' => 'a@example.com',
            'password' => 'secret',
            'remember' => 'sometimes',
        ]));
    }

    /** @param array<string, mixed> $body */
    private function request(array $body): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn($body);

        return $request;
    }
}
