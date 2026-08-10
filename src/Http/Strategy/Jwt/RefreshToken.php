<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

final readonly class RefreshToken
{
    public bool $revoked;

    public function __construct(
        public string $id,
        public string $userId,
        public string $familyId,
        public int $expiresAt,
        public ?int $revokedAt = null,
    ) {
        $this->revoked = $this->revokedAt !== null;
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }
}
