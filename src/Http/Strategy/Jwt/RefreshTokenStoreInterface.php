<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\UuidInterface;

/**
 * Persistent refresh-grant storage with durable family compromise state.
 */
interface RefreshTokenStoreInterface
{
    public function storeInitial(RefreshToken $token): void;

    /**
     * Rotation, replay detection, family compromise and successor creation are
     * one serialized transition. Replay must leave no active descendant.
     */
    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult;

    public function revoke(string $tokenId, int $revokedAt): void;

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void;
}
