<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class BearerExtractor implements PayloadExtractorInterface
{
    private const int MAX_TOKEN_LENGTH = 8192;

    public function __construct(
        public string $header = 'Authorization',
    ) {}

    #[\Override]
    public function extract(ServerRequestInterface $request): ?object
    {
        $value = $request->getHeaderLine($this->header);

        if ($value === '') {
            return null;
        }

        if (strlen($value) < 7 || strcasecmp(substr($value, 0, 7), 'Bearer ') !== 0) {
            return null;
        }

        $token = substr($value, 7);

        if (
            $token === ''
            || strlen($token) > self::MAX_TOKEN_LENGTH
            || trim($token) !== $token
            || preg_match('/\s/', $token) === 1
        ) {
            throw InvalidPayloadException::invalidField($this->header);
        }

        return new BearerPayload($token);
    }
}
