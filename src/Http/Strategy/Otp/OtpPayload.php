<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Payload for OTP verification step.
 *
 * Contains the destination (used to look up the stored code)
 * and the code entered by the user.
 *
 * The code is masked in every serialization path (var_dump, json_encode,
 * stack traces) so that listeners, loggers, or error trackers cannot
 * leak it accidentally when they capture authentication events.
 */
final readonly class OtpPayload implements \JsonSerializable
{
    public function __construct(
        public string $destination,
        #[\SensitiveParameter]
        public string $code,
    ) {}

    /**
     * @return array{destination: string, code: string}
     */
    public function __debugInfo(): array
    {
        return [
            'destination' => $this->destination,
            'code' => '[REDACTED]',
        ];
    }

    /**
     * @return array{destination: string, code: string}
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
