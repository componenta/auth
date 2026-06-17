<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

/**
 * Thrown when the payload is invalid or missing required data.
 *
 * This indicates a programming error where the extractor
 * and authenticator/strategy expectations don't match.
 */
class InvalidPayloadException extends AuthenticationException
{
    public function __construct(
        string $message,
        public readonly ?object $payload = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Missing required field in payload data.
     */
    public static function missingField(string $field, ?object $payload = null): self
    {
        return new self(sprintf('Missing required field: %s', $field), $payload);
    }
}