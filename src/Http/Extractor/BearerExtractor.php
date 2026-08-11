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
    ) {
        if (preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $this->header) !== 1) {
            throw new \InvalidArgumentException('Bearer header name is invalid.');
        }
    }

    #[\Override]
    public function extract(ServerRequestInterface $request): ?object
    {
        $value = $request->getHeaderLine($this->header);

        if ($value === '') {
            return null;
        }

        if (strncasecmp($value, 'Bearer', 6) !== 0) {
            return null;
        }

        if (strlen($value) < 7 || $value[6] !== ' ') {
            throw InvalidPayloadException::invalidField($this->header);
        }

        $offset = 6;

        while (($value[$offset] ?? null) === ' ') {
            ++$offset;
        }

        $token = substr($value, $offset);

        if (
            $token === ''
            || strlen($token) > self::MAX_TOKEN_LENGTH
            || trim($token) !== $token
            || preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/D', $token) !== 1
        ) {
            throw InvalidPayloadException::invalidField($this->header);
        }

        return new BearerPayload($token);
    }
}
