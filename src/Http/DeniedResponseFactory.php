<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\DeniedReasonInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/** Maps denial reasons to bounded code-only JSON responses. */
final readonly class DeniedResponseFactory implements DeniedResponseFactoryInterface
{
    private const string FALLBACK_CODE = 'authentication_denied';

    /** @param array<string, int> $statusMap */
    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private array $statusMap = [],
        private int $defaultStatus = 401,
    ) {
        if ($this->defaultStatus < 400 || $this->defaultStatus > 599) {
            throw new \InvalidArgumentException(
                'The default denial status must be an HTTP error status.',
            );
        }

        foreach ($this->statusMap as $code => $status) {
            if (!self::validCode($code) || $status < 400 || $status > 599) {
                throw new \InvalidArgumentException(
                    'Every denial status mapping must use a valid code and HTTP error status.',
                );
            }
        }
    }

    #[\Override]
    public function create(DeniedReasonInterface $reason): ResponseInterface
    {
        $code = self::validCode($reason->code)
            ? $reason->code
            : self::FALLBACK_CODE;
        $status = $this->statusMap[$code] ?? $this->defaultStatus;
        $json = json_encode(['error' => $code], JSON_THROW_ON_ERROR);
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write($json);

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }

    private static function validCode(string $code): bool
    {
        return preg_match('/\A[a-z0-9][a-z0-9._-]{0,127}\z/D', $code) === 1;
    }
}
