<?php

declare(strict_types=1);

namespace Componenta\Auth\Tests\PasswordReset;

use Componenta\Auth\PasswordReset\PasswordResetResult;
use Componenta\Auth\PasswordReset\PasswordResetServiceInterface;
use Componenta\Auth\PasswordReset\ResetPasswordHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

final class ResetPasswordHandlerTest extends TestCase
{
    public function testDelegatesOneCompletedSecurityTransitionToResetService(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'token' => 'reset-token',
            'password' => 'new-password',
            'passwordConfirmation' => 'new-password',
        ]);
        $service = $this->createMock(PasswordResetServiceInterface::class);
        $service->expects(self::once())->method('reset')
            ->with('reset-token', 'new-password')
            ->willReturn(PasswordResetResult::Success);
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(200)
            ->willReturn($response);

        self::assertSame($response, (new ResetPasswordHandler($service, $responseFactory))->handle($request));
    }
}
