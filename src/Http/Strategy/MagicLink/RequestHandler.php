<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RequestHandler implements RequestHandlerInterface
{
    private const int MAX_IDENTITY_LENGTH = 320;

    public function __construct(
        private TokenRequestQueueInterface $queue,
        private ResponseFactoryInterface $responseFactory,
        private string $identityField = 'identity',
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $this->identityField) !== 1) {
            throw new \InvalidArgumentException('Magic-link identity field name is invalid.');
        }
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody();
        $identity = is_array($body) ? ($body[$this->identityField] ?? null) : null;

        if (
            !is_string($identity)
            || $identity === ''
            || strlen($identity) > self::MAX_IDENTITY_LENGTH
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            return $this->json(400, ['error' => 'invalid_identity']);
        }

        if (array_key_exists('redirect', $body)) {
            return $this->json(400, ['error' => 'redirect_not_supported']);
        }

        $this->queue->enqueue(new TokenRequest(
            identity: $identity,
            purpose: TokenRequest::PURPOSE_MAGIC_LINK,
        ));

        return $this->json(200, ['message' => 'If the account exists, a link has been sent.']);
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
