<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class ForgotPasswordHandler implements RequestHandlerInterface
{
    private const int MAX_IDENTITY_LENGTH = 320;

    public function __construct(
        private TokenRequestQueueInterface $queue,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody();
        $email = is_array($body) ? ($body['email'] ?? null) : null;

        if (!is_string($email) || $email === '' || strlen($email) > self::MAX_IDENTITY_LENGTH) {
            return $this->json(400, ['error' => 'invalid_email']);
        }

        $this->queue->enqueue(new TokenRequest($email));

        return $this->json(200, [
            'message' => 'If the account exists, a reset link has been sent.',
        ]);
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
