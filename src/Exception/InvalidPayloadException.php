<?php

declare(strict_types=1);

namespace Componenta\Auth\Exception;

class InvalidPayloadException extends AuthenticationException
{
    public function __construct(
        string $message,
        public readonly ?object $payload = null,
        public readonly ?string $field = null,
    ) {
        parent::__construct($message);
    }

    public static function missingField(string $field, ?object $payload = null): self
    {
        return new self(sprintf('Missing required field: %s', $field), $payload, $field);
    }

    public static function invalidField(string $field, ?object $payload = null): self
    {
        return new self(sprintf('Invalid field: %s', $field), $payload, $field);
    }
}
