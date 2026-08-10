<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

use Componenta\Stdlib\PasswordHasherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class ResetPasswordHandler implements RequestHandlerInterface
{
    private const int MAX_TOKEN_LENGTH = 512;
    private const int MAX_PASSWORD_LENGTH = 4096;

    public function __construct(
        private PasswordResetServiceInterface $resetService,
        private PasswordHasherInterface $passwordHasher,
        private ResponseFactoryInterface $responseFactory,
        private int $minPasswordLength = 8,
    ) {
        if ($this->minPasswordLength < 1) {
            throw new \InvalidArgumentException('Minimum password length must be positive.');
        }
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $parsed = $request->getParsedBody();
        $body = is_array($parsed) ? $parsed : [];
        $token = $body['token'] ?? null;
        $password = $body['password'] ?? null;
        $passwordConfirmation = $body['passwordConfirmation'] ?? null;
        $errors = [];

        if (!is_string($token) || $token === '' || strlen($token) > self::MAX_TOKEN_LENGTH) {
            $errors['token'] = ['Token is invalid.'];
        }

        if (!is_string($password) || $password === '') {
            $errors['password'] = ['Password is required.'];
        } elseif (strlen($password) > self::MAX_PASSWORD_LENGTH) {
            $errors['password'] = ['Password is too long.'];
        } elseif (mb_strlen($password) < $this->minPasswordLength) {
            $errors['password'] = [
                sprintf('Password must be at least %d characters long.', $this->minPasswordLength),
            ];
        }

        if (!is_string($passwordConfirmation) || $passwordConfirmation !== $password) {
            $errors['passwordConfirmation'] = ['Passwords do not match.'];
        }

        if ($errors !== []) {
            return $this->json(422, ['errors' => $errors]);
        }

        /** @var string $token */
        /** @var string $password */
        $result = $this->resetService->reset($token, $this->passwordHasher->hash($password));

        if ($result === PasswordResetResult::InvalidToken) {
            return $this->json(400, ['error' => 'invalid_token']);
        }

        return $this->json(200, ['message' => 'Password has been reset successfully.']);
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
