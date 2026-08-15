<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Extractor;

use Componenta\Auth\Http\BearerCredential;

/** Bearer credential payload with redacted serialization. */
final readonly class BearerPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
    ) {
        BearerCredential::assertValid($this->token);
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
