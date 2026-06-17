<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles refresh token revocation.
 *
 * Accepts a refresh_token in the request body and revokes it.
 * Always returns 200 regardless of whether the token exists
 * (RFC 7009 - do not reveal token existence).
 */
final readonly class RevokeHandler implements RequestHandlerInterface
{
    public function __construct(
        private RefreshTokenManager $refreshManager,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = (array) $request->getParsedBody();
        $tokenId = $body['refresh_token'] ?? null;

        if (is_string($tokenId) && $tokenId !== '') {
            $this->refreshManager->revoke($tokenId);
        }

        return $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json');
    }
}
