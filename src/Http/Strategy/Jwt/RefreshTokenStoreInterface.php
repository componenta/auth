<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * Persistent refresh-grant storage.
 *
 * Implementations must keep durable family/grant state. Rotation, replay
 * detection, family compromise and successor creation are one serialized
 * transaction (or one atomic server-side script), not independent calls.
 */
interface RefreshTokenStoreInterface
{
    /** Persists the first token of a new family. */
    public function storeInitial(RefreshToken $token): void;

    /**
     * Atomically rotates a token.
     *
     * On a replay, the operation must mark the family compromised and leave
     * no active descendant. A concurrent transaction must not be able to
     * insert a successor after the compromise transition commits.
     */
    public function rotateAtomically(
        string $presentedTokenId,
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult;

    public function revoke(string $tokenId, int $revokedAt): void;

    public function revokeAllForUser(string $userId, int $revokedAt): void;
}
