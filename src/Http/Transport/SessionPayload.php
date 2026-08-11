<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Transport;

/** Session and optional remember-me credential transport payload. */
final readonly class SessionPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public ?string $sessionId = null,
        #[\SensitiveParameter]
        public ?string $rememberMeToken = null,
    ) {
        if ($this->sessionId !== null) {
            self::assertCredential($this->sessionId, 512, 'Session ID');
        }

        if ($this->rememberMeToken !== null) {
            self::assertCredential($this->rememberMeToken, 4096, 'Remember-me token');
        }
    }

    /** @return array{sessionId: string|null, rememberMeToken: string|null} */
    public function __debugInfo(): array
    {
        return [
            'sessionId' => self::redact($this->sessionId),
            'rememberMeToken' => self::redact($this->rememberMeToken),
        ];
    }

    /** @return array{sessionId: string|null, rememberMeToken: string|null} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    private static function assertCredential(
        string $value,
        int $maxLength,
        string $label,
    ): void {
        if (
            $value === ''
            || strlen($value) > $maxLength
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }

    private static function redact(?string $value): ?string
    {
        return $value === null ? null : '[REDACTED]';
    }
}
