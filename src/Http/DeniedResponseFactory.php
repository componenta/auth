<?php

declare(strict_types=1);

namespace Componenta\Auth\Http;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\PublicDeniedReasonInterface;
use JsonException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/** Maps denial reasons to bounded, allowlisted JSON responses. */
final readonly class DeniedResponseFactory implements DeniedResponseFactoryInterface
{
    private const string FALLBACK_CODE = 'authentication_denied';
    private const int MAX_DETAIL_STRING_LENGTH = 2048;

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
        /** @var array{error: string, details?: array<string, bool|float|int|string|null>} $payload */
        $payload = ['error' => $code];

        if ($reason instanceof PublicDeniedReasonInterface) {
            $details = self::sanitizePublicDetails($reason->publicDetails);

            if ($details !== []) {
                $payload['details'] = $details;
            }
        }

        try {
            $json = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $json = '{"error":"' . self::FALLBACK_CODE . '"}';
        }

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

    /**
     * @param array<string, mixed> $details
     * @return array<string, bool|float|int|string|null>
     */
    private static function sanitizePublicDetails(array $details): array
    {
        $safe = [];

        foreach ($details as $key => $value) {
            if (
                !is_string($key)
                || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\z/D', $key) !== 1
            ) {
                continue;
            }

            if (is_string($value)) {
                if (
                    strlen($value) > self::MAX_DETAIL_STRING_LENGTH
                    || preg_match('//u', $value) !== 1
                    || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $value) === 1
                ) {
                    continue;
                }
            } elseif (is_float($value)) {
                if (!is_finite($value)) {
                    continue;
                }
            } elseif (!is_int($value) && !is_bool($value) && $value !== null) {
                continue;
            }

            $safe[$key] = $value;
        }

        return $safe;
    }
}
