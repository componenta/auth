<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Identity\UuidInterface;

/**
 * Persistent refresh-grant storage with durable family terminal state.
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

    /**
     * Performs ordinary revocation of the presented token's complete family.
     * It must serialize with rotation so a successor created concurrently
     * cannot escape revocation. Ordinary revocation is terminal but must not
     * mark the family as replay-compromised.
     */
    public function revoke(string $tokenId, int $revokedAt): void;

    /**
     * Revokes every existing refresh family for the subject. Implementations
     * must serialize with rotations of those families so no existing family can
     * retain an active descendant after the transition.
     */
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void;
}
