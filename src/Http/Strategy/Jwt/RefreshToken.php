<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\UuidInterface;

final readonly class RefreshToken implements \JsonSerializable
{
    public bool $revoked;

    public function __construct(
        #[\SensitiveParameter]
        public string $id,
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
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

    /**
     * @return array{
     *     id: string,
     *     subjectId: string,
     *     familyId: string,
     *     expiresAt: int,
     *     revokedAt: int|null,
     *     revoked: bool
     * }
     */
    public function __debugInfo(): array
    {
        return [
            'id' => '[REDACTED]',
            'subjectId' => $this->subjectId->toString(),
            'familyId' => '[REDACTED]',
            'expiresAt' => $this->expiresAt,
            'revokedAt' => $this->revokedAt,
            'revoked' => $this->revoked,
        ];
    }

    /**
     * @return array{
     *     id: string,
     *     subjectId: string,
     *     familyId: string,
     *     expiresAt: int,
     *     revokedAt: int|null,
     *     revoked: bool
     * }
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
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
