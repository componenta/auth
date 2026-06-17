<?php

declare(strict_types=1);

namespace Componenta\Auth\PasswordReset;

use Componenta\Auth\Token\TokenRequester;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles password reset request (forgot password) step.
 *
 * Extracts the user email from the request body and
 * delegates to PasswordResetRequester to generate and send the token.
 *
 * Always returns 200 regardless of whether the user exists,
 * to prevent user enumeration attacks.
 */
final readonly class ForgotPasswordHandler implements RequestHandlerInterface
{
    public function __construct(
        private TokenRequester $requester,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        if (!is_array($body)) {
            $body = get_object_vars($body);
        }

        $email = $body['email'] ?? null;

        if ($email === null || $email === '') {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(
                json_encode(['error' => 'missing_email'], JSON_THROW_ON_ERROR),
            );

            return $response->withHeader('Content-Type', 'application/json');
        }

        $this->requester->request($email);

        $response = $this->responseFactory->createResponse(200);
        $response->getBody()->write(json_encode([
            'message' => 'If the account exists, a reset link has been sent.',
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
