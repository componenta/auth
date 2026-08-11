<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\UuidInterface;

final readonly class RefreshToken
{
    public bool $revoked;

    public function __construct(
        public string $id,
        public UuidInterface $subjectId,
        public string $familyId,
        public int $expiresAt,
        public ?int $revokedAt = null,
    ) {
        if (!self::validIdentifier($this->id)) {
            throw new \InvalidArgumentException('Refresh token ID is invalid.');
        }

        if (!self::validIdentifier($this->familyId)) {
            throw new \InvalidArgumentException('Refresh token family ID is invalid.');
        }

        if ($this->expiresAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token expiry must be positive.',
            );
        }

        if ($this->revokedAt !== null && $this->revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $this->revoked = $this->revokedAt !== null;
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }

    private static function validIdentifier(string $value): bool
    {
        return preg_match('/\A[a-f0-9]{64,128}\z/D', $value) === 1
            && strlen($value) % 2 === 0;
    }
}
