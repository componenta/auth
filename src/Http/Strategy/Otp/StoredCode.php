<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Identity\UuidInterface;

final readonly class StoredCode implements \JsonSerializable
{
    public function __construct(
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
        public string $code,
        public string $destination,
        public int $expiresAt,
        public int $attempts = 0,
    ) {
        if (preg_match(sprintf(
            '/\A[0-9]{%d,%d}\z/D',
            OtpConfig::MIN_LENGTH,
            OtpConfig::MAX_LENGTH,
        ), $this->code) !== 1) {
            throw new \InvalidArgumentException('Stored OTP code is invalid.');
        }

        if (
            $this->destination === ''
            || strlen($this->destination) > 320
            || trim($this->destination) !== $this->destination
            || preg_match('/[\x00-\x1F\x7F]/', $this->destination) === 1
        ) {
            throw new \InvalidArgumentException('Stored OTP destination is invalid.');
        }

        if ($this->expiresAt < 1) {
            throw new \InvalidArgumentException('OTP expiry must be positive.');
        }

        if ($this->attempts < 0) {
            throw new \InvalidArgumentException('OTP attempts must not be negative.');
        }
    }

    /** @return array{subjectId: string, code: string, destination: string, expiresAt: int, attempts: int} */
    public function __debugInfo(): array
    {
        return [
            'subjectId' => $this->subjectId->toString(),
            'code' => '[REDACTED]',
            'destination' => $this->destination,
            'expiresAt' => $this->expiresAt,
            'attempts' => $this->attempts,
        ];
    }

    /** @return array{subjectId: string, code: string, destination: string, expiresAt: int, attempts: int} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
