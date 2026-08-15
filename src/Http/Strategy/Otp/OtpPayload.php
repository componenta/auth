<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/** OTP verification payload with redacted serialization. */
final readonly class OtpPayload implements \JsonSerializable
{
    public function __construct(
        public string $destination,
        #[\SensitiveParameter]
        public string $code,
    ) {
        if (
            $this->destination === ''
            || strlen($this->destination) > 320
            || trim($this->destination) !== $this->destination
            || preg_match('/[\x00-\x1F\x7F]/', $this->destination) === 1
        ) {
            throw new \InvalidArgumentException('OTP destination is invalid.');
        }

        if (preg_match(sprintf(
            '/\A[0-9]{%d,%d}\z/D',
            OtpConfig::MIN_LENGTH,
            OtpConfig::MAX_LENGTH,
        ), $this->code) !== 1) {
            throw new \InvalidArgumentException('OTP code is invalid.');
        }
    }

    /** @return array{destination: string, code: string} */
    public function __debugInfo(): array
    {
        return [
            'destination' => $this->destination,
            'code' => '[REDACTED]',
        ];
    }

    /** @return array{destination: string, code: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
