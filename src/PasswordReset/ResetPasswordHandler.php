<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

use Componenta\Auth\Session\SessionManagerInterface;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Stdlib\PasswordHasherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles the actual password reset step.
 *
 * Extracts token and new password from the request body.
 * Validates the token, hashes the new password, updates it,
 * and terminates all user sessions.
 */
final readonly class ResetPasswordHandler implements RequestHandlerInterface
{
    public function __construct(
        private TokenManagerInterface $tokenManager,
        private PasswordUpdaterInterface $passwordUpdater,
        private PasswordHasherInterface $passwordHasher,
        private SessionManagerInterface $sessionManager,
        private ResponseFactoryInterface $responseFactory,
        /** Minimum length of the new password in characters (UTF-8 code points). */
        private int $minPasswordLength = 8,
    ) {
        if ($this->minPasswordLength < 1) {
            throw new \InvalidArgumentException('Minimum password length must be positive');
        }
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        if (!is_array($body)) {
            $body = get_object_vars($body);
        }

        $token = $body['token'] ?? null;
        $password = $body['password'] ?? null;
        $passwordConfirmation = $body['passwordConfirmation'] ?? null;

        // Validate required fields
        $errors = [];

        if (!is_string($token) || $token === '') {
            $errors['token'] = ['Token is required.'];
        }

        if (!is_string($password) || $password === '') {
            $errors['password'] = ['Password is required.'];
        } elseif (mb_strlen($password) < $this->minPasswordLength) {
            $errors['password'] = [
                sprintf('Password must be at least %d characters long.', $this->minPasswordLength),
            ];
        }

        if ($passwordConfirmation !== $password) {
            $errors['passwordConfirmation'] = ['Passwords do not match.'];
        }

        if ($errors !== []) {
            return $this->errorResponse(422, ['errors' => $errors]);
        }

        // Find and atomically consume the token
        $tokenRecord = $this->tokenManager->find($token);

        if ($tokenRecord === null) {
            return $this->errorResponse(400, ['error' => 'invalid_token']);
        }

        if (!$this->tokenManager->consume($token)) {
            return $this->errorResponse(400, ['error' => 'invalid_token']);
        }

        // Hash and update the password
        $passwordHash = $this->passwordHasher->hash($password);
        $this->passwordUpdater->updatePassword($tokenRecord->userId, $passwordHash);

        // Terminate all sessions
        $this->sessionManager->terminateAll($tokenRecord->userId);

        $response = $this->responseFactory->createResponse(200);
        $response->getBody()->write(json_encode([
            'message' => 'Password has been reset successfully.',
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }

    /**
     * @param array<string, mixed> $data
     */
    private function errorResponse(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
