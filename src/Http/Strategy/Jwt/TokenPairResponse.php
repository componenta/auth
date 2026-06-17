<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Creates HTTP response containing a JWT access/refresh token pair.
 *
 * Shared helper used by all strategy-specific token handlers
 * to avoid duplicating the response building logic.
 *
 * Response format:
 * {
 *   "access_token": "eyJ...",
 *   "refresh_token": "a1b2c3...",
 *   "token_type": "Bearer",
 *   "expires_in": 900
 * }
 */
final readonly class TokenPairResponse
{
    public function __construct(
        private SignerInterface $signer,
        private RefreshTokenManager $refreshManager,
        private JwtConfig $config,
        private ResponseFactoryInterface $responseFactory,
        private ClockInterface $clock = new Clock(),
    ) {}

    /**
     * Creates a response with a new token pair for the authenticated user.
     */
    public function create(IdentityInterface $user): ResponseInterface
    {
        $now = $this->clock->now()->getTimestamp();
        $subjectId = $user->uuid->toString();

        $claims = new Claims(
            subject: $subjectId,
            issuedAt: $now,
            expiresAt: $now + $this->config->accessTtl,
            issuer: $this->config->issuer,
            audience: $this->config->audience,
        );

        $accessToken = $this->signer->sign($claims);
        $refreshToken = $this->refreshManager->issue($subjectId);

        $response = $this->responseFactory->createResponse(200);
        $response->getBody()->write(json_encode([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken->id,
            'token_type' => 'Bearer',
            'expires_in' => $this->config->accessTtl,
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
