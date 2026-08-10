<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\PasswordReset;

use Componenta\Auth\PasswordReset\PasswordResetResult;
use Componenta\Auth\PasswordReset\PasswordResetServiceInterface;
use Componenta\Auth\PasswordReset\ResetPasswordHandler;
use Componenta\Stdlib\PasswordHasherInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class ResetPasswordHandlerTest extends TestCase
{
    public function testDelegatesOneCompletedSecurityTransitionToResetService(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'token' => 'reset-token',
            'password' => 'new-password',
            'passwordConfirmation' => 'new-password',
        ]);
        $hasher = $this->createMock(PasswordHasherInterface::class);
        $hasher->expects(self::once())->method('hash')->with('new-password')->willReturn('hash');
        $service = $this->createMock(PasswordResetServiceInterface::class);
        $service->expects(self::once())->method('reset')
            ->with('reset-token', 'hash')
            ->willReturn(PasswordResetResult::Success);
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')->with(200)->willReturn($response);

        self::assertSame($response, (new ResetPasswordHandler($service, $hasher, $responseFactory))->handle($request));
    }
}
