<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequest
{
    /** @param array<string, string> $context */
    public function __construct(
        public string $identity,
        public ?string $destination = null,
        public array $context = [],
    ) {
        self::assertAddress($this->identity, 'Token request identity');

        if ($this->destination !== null) {
            self::assertAddress($this->destination, 'Token request destination');
        }

        foreach ($this->context as $key => $value) {
            if (
                !is_string($key)
                || !is_string($value)
                || $key === ''
                || strlen($key) > 128
                || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D', $key) !== 1
                || strlen($value) > 4096
                || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) === 1
            ) {
                throw new \InvalidArgumentException('Token request context is invalid.');
            }
        }
    }

    private static function assertAddress(string $value, string $label): void
    {
        if (
            $value === ''
            || strlen($value) > 320
            || trim($value) !== $value
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }
}
