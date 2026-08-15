<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\Http\BearerCredential;
use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final readonly class TokenPairResponse
{
    public function __construct(
        private SignerInterface $signer,
        private RefreshTokenManager $refreshManager,
        private JwtConfig $config,
        private ResponseFactoryInterface $responseFactory,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function create(IdentityInterface $identity): ResponseInterface
    {
        $now = $this->clock->now()->getTimestamp();
        $subjectId = $identity->uuid->toString();
        $accessToken = $this->signer->sign(new Claims(
            subject: $subjectId,
            issuedAt: $now,
            expiresAt: $now + $this->config->accessTtl,
            issuer: $this->config->issuer,
            audience: $this->config->audience,
            type: $this->config->type,
        ));
        BearerCredential::assertValid($accessToken);

        // Allocate every fallible response object before the durable refresh
        // issuance. After issue(), any response-side failure is compensated by
        // ordinary family revocation because the client never learned the
        // bearer value.
        $response = $this->responseFactory->createResponse(200);
        $refreshToken = $this->refreshManager->issue($identity->uuid);

        try {
            $response->getBody()->write(json_encode([
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken->id,
                'token_type' => 'Bearer',
                'expires_in' => $this->config->accessTtl,
            ], JSON_THROW_ON_ERROR));

            return TokenResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            $this->refreshManager->revoke($refreshToken->id);
            throw $exception;
        }
    }
}
