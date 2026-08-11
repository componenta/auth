<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

/** Magic-link credential payload with redacted serialization. */
final readonly class VerifyPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
    ) {
        if (preg_match('/\A[a-f0-9]{64}\z/D', $this->token) !== 1) {
            throw new \InvalidArgumentException('Magic-link token is invalid.');
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
