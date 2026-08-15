<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

/** Extracts one bounded opaque magic-link credential from a POST body. */
final readonly class VerifyExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $tokenField = 'token',
    ) {
        if (
            $this->tokenField === ''
            || preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $this->tokenField) !== 1
        ) {
            throw new \InvalidArgumentException('Token field is invalid.');
        }
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ?VerifyPayload {
        if (strtoupper($request->getMethod()) !== 'POST') {
            return null;
        }

        $body = $request->getParsedBody();

        if ($body === null) {
            return null;
        }

        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        if (!array_key_exists($this->tokenField, $body)) {
            return null;
        }

        return $this->payload($body[$this->tokenField]);
    }

    private function payload(
        #[\SensitiveParameter]
        mixed $token,
    ): VerifyPayload {
        if (!is_string($token) || preg_match('/\A[a-f0-9]{64}\z/D', $token) !== 1) {
            throw InvalidPayloadException::invalidField($this->tokenField);
        }

        return new VerifyPayload($token);
    }
}