<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

/**
 * Persistent storage for refresh tokens.
 *
 * Implementations may use a database table, Redis, or other
 * persistent storage. The interface is defined in the library;
 * the implementation lives in the application.
 */
interface RefreshTokenStoreInterface
{
    /**
     * Persists a new refresh token.
     */
    public function store(RefreshToken $token): void;

    /**
     * Finds a refresh token by its identifier.
     *
     * Returns the token regardless of its revocation status -
     * the caller decides how to handle revoked tokens.
     */
    public function find(string $tokenId): ?RefreshToken;

    /**
     * Revokes a single refresh token unconditionally.
     *
     * @param string $tokenId Token identifier
     * @param int $revokedAt Revocation timestamp
     */
    public function revoke(string $tokenId, int $revokedAt): void;

    /**
     * Atomically revokes a token only if it is currently active.
     *
     * Must be implemented as a single compare-and-swap SQL statement,
     * e.g. `UPDATE ... SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
     * returning true only when exactly one row was updated.
     *
     * Used by rotation to detect concurrent reuse: if two requests try to
     * rotate the same token, only one revokeIfActive() returns true; the
     * loser treats this as a reuse signal and revokes the whole family.
     *
     * @return bool True if the token was active and got revoked in this call;
     *              false if it was already revoked (or did not exist).
     */
    public function revokeIfActive(string $tokenId, int $revokedAt): bool;

    /**
     * Revokes all tokens in a family.
     *
     * Used for reuse detection: when a revoked token is presented,
     * all tokens in the same family are revoked as a precaution.
     *
     * @param string $familyId Family identifier
     * @param int $revokedAt Revocation timestamp
     */
    public function revokeFamily(string $familyId, int $revokedAt): void;
}
