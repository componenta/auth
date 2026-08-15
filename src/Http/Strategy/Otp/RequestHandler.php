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
        private OtpRequestQueueInterface $queue,
        private ResponseFactoryInterface $responseFactory,
        private string $identityField = 'destination',
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $this->identityField) !== 1) {
            throw new \InvalidArgumentException('OTP identity field name is invalid.');
        }
    }

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
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

        $work = new OtpRequest($identity);
        $response = $this->json(200, [
            'message' => 'If the account exists, a code has been sent.',
        ]);

        $this->queue->enqueue($work);

        return $response;
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
