<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

final readonly class Claims
{
    /** @param array<string, mixed> $custom */
    public function __construct(
        public string $subject,
        public int $issuedAt,
        public int $expiresAt,
        public string $issuer,
        public string $audience,
        public string $type = 'at+jwt',
        public ?int $notBefore = null,
        public array $custom = [],
    ) {
        if ($this->subject === '') {
            throw new \InvalidArgumentException('JWT subject must not be empty.');
        }

        if ($this->expiresAt <= $this->issuedAt) {
            throw new \InvalidArgumentException('JWT expiration must be later than issued-at.');
        }

        if ($this->issuer === '' || $this->audience === '' || $this->type === '') {
            throw new \InvalidArgumentException('JWT issuer, audience and type are required.');
        }
    }
}
