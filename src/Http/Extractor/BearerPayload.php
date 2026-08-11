<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

/** Bearer credential payload with redacted serialization. */
final readonly class BearerPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
    ) {
        if (
            strlen($this->token) > 8192
            || preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/D', $this->token) !== 1
        ) {
            throw new \InvalidArgumentException('Bearer token is invalid.');
        }
    }

    /** @return array{token: string} */
    public function __debugInfo(): array
    {
        return ['token' => '[REDACTED]'];
    }

    /** @return array{token: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
