<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\Token\TokenRequester;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RequestHandler implements RequestHandlerInterface
{
    private const int MAX_IDENTITY_LENGTH = 320;
    private const int MAX_REDIRECT_LENGTH = 2048;

    public function __construct(
        private TokenRequester $requester,
        private ResponseFactoryInterface $responseFactory,
        private string $identityField = 'identity',
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $parsed = $request->getParsedBody();
        $body = is_array($parsed) ? $parsed : [];
        $identity = $body[$this->identityField] ?? null;

        if (!is_string($identity) || $identity === '' || strlen($identity) > self::MAX_IDENTITY_LENGTH) {
            return $this->json(400, ['error' => 'invalid_identity']);
        }

        $context = [];
        $redirect = $body['redirect'] ?? null;
        if (is_string($redirect) && $redirect !== '' && strlen($redirect) <= self::MAX_REDIRECT_LENGTH) {
            $context['redirect'] = $redirect;
        }
        $this->requester->request($identity, context: $context);

        return $this->json(200, ['message' => 'If the account exists, a link has been sent.']);
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
