<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RequestHandler implements RequestHandlerInterface
{
    private const int MAX_IDENTITY_LENGTH = 320;

    public function __construct(
        private OtpRequester $requester,
        private ResponseFactoryInterface $responseFactory,
        private string $identityField = 'destination',
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $parsed = $request->getParsedBody();
        $body = is_array($parsed) ? $parsed : [];
        $identity = $body[$this->identityField] ?? null;

        if (!is_string($identity) || $identity === '' || strlen($identity) > self::MAX_IDENTITY_LENGTH) {
            return $this->json(400, ['error' => 'invalid_identity']);
        }

        $this->requester->request($identity);
        return $this->json(200, ['message' => 'If the account exists, a code has been sent.']);
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
