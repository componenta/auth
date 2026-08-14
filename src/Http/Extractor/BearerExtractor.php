<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\BearerCredential;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class BearerExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $header = 'Authorization',
    ) {
        if (preg_match('/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+\z/D', $this->header) !== 1) {
            throw new \InvalidArgumentException('Bearer header name is invalid.');
        }
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?object {
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

        if (!BearerCredential::isValid($token)) {
            throw InvalidPayloadException::invalidField($this->header);
        }

        return new BearerPayload($token);
    }
}
