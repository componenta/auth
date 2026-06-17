<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

/**
 * Payload for the magic link verify step.
 *
 * The token is masked in every serialization path (var_dump, json_encode,
 * stack traces) so that listeners, loggers, or error trackers cannot leak
 * it accidentally when they capture authentication events.
 */
final readonly class VerifyPayload implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
    ) {}

    /**
     * @return array{token: string}
     */
    public function __debugInfo(): array
    {
        return ['token' => '[REDACTED]'];
    }

    /**
     * @return array{token: string}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
