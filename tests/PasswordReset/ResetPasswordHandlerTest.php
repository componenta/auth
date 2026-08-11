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
        $request = $this->request('new-password');
        $service = $this->createMock(PasswordResetServiceInterface::class);
        $service->expects(self::once())->method('reset')
            ->with('reset-token', 'new-password')
            ->willReturn(PasswordResetResult::Success);
        [$responseFactory, $response] = $this->responseFactory(200);

        self::assertSame(
            $response,
            (new ResetPasswordHandler($service, $responseFactory))->handle($request),
        );
    }

    public function testApplicationPasswordPolicyCanRejectOtherwiseValidInput(): void
    {
        $request = $this->request('shortpw');
        $service = $this->createMock(PasswordResetServiceInterface::class);
        $service->expects(self::once())->method('reset')
            ->with('reset-token', 'shortpw')
            ->willReturn(PasswordResetResult::PasswordRejected);
        [$responseFactory, $response] = $this->responseFactory(422);

        self::assertSame(
            $response,
            (new ResetPasswordHandler($service, $responseFactory))->handle($request),
        );
    }

    private function request(string $password): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'token' => 'reset-token',
            'password' => $password,
            'passwordConfirmation' => $password,
        ]);

        return $request;
    }

    /** @return array{ResponseFactoryInterface, ResponseInterface} */
    private function responseFactory(int $status): array
    {
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturn(1);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('withHeader')->willReturnSelf();
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with($status)
            ->willReturn($response);

        return [$responseFactory, $response];
    }
}
