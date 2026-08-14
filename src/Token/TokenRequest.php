<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/** Queue message for one identity-as-destination one-time-token purpose. */
final readonly class TokenRequest
{
    public const string PURPOSE_MAGIC_LINK = 'magic_link';
    public const string PURPOSE_PASSWORD_RESET = 'password_reset';

    /** @param array<string, string> $context */
    public function __construct(
        public string $identity,
        public string $purpose,
        public array $context = [],
    ) {
        self::assertAddress($this->identity, 'Token request identity');
        self::assertPurpose($this->purpose);

        foreach ($this->context as $key => $value) {
            if (
                !is_string($key)
                || !is_string($value)
                || $key === ''
                || strlen($key) > 128
                || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D', $key) !== 1
                || strlen($value) > 4096
                || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
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

    private static function assertPurpose(string $purpose): void
    {
        if (preg_match('/\A[a-z][a-z0-9._-]{0,63}\z/D', $purpose) !== 1) {
            throw new \InvalidArgumentException(
                'Token request purpose must be a bounded machine-readable identifier.',
            );
        }
    }
}
