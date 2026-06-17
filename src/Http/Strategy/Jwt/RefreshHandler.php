<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles refresh token rotation.
 *
 * Accepts a refresh_token in the request body, rotates it
 * (revokes old, issues new), and returns a fresh token pair.
 *
 * If the presented token was already revoked, the entire token
 * family is revoked (reuse detection).
 */
final readonly class RefreshHandler implements RequestHandlerInterface
{
    public function __construct(
        private RefreshTokenManager $refreshManager,
        private JwtUserProviderInterface $provider,
        private SignerInterface $signer,
        private JwtConfig $config,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = (array) $request->getParsedBody();
        $tokenId = $body['refresh_token'] ?? null;

        if (!is_string($tokenId) || $tokenId === '') {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(
                json_encode(['error' => 'missing_refresh_token'], JSON_THROW_ON_ERROR)
            );

            return $response->withHeader('Content-Type', 'application/json');
        }

        $result = $this->refreshManager->rotate($tokenId);

        if ($result instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result);
        }

        $user = $this->provider->findById($result->userId);

        if ($user === null) {
            return $this->deniedResponseFactory->create(new InvalidRefreshToken());
        }

        $now = $this->clock->now()->getTimestamp();
        $claims = new Claims(
            subject: $user->uuid->toString(),
            issuedAt: $now,
            expiresAt: $now + $this->config->accessTtl,
            issuer: $this->config->issuer,
            audience: $this->config->audience,
        );

        $accessToken = $this->signer->sign($claims);

        $response = $this->responseFactory->createResponse(200);
        $response->getBody()->write(json_encode([
            'access_token' => $accessToken,
            'refresh_token' => $result->id,
            'token_type' => 'Bearer',
            'expires_in' => $this->config->accessTtl,
        ], JSON_THROW_ON_ERROR));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
