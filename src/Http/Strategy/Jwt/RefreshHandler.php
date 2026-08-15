<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt;

use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\BearerCredential;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\Denied\InvalidRefreshToken;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RefreshHandler implements RequestHandlerInterface
{
    private const int MAX_REFRESH_TOKEN_LENGTH = 128;

    public function __construct(
        private RefreshTokenManager $refreshManager,
        private JwtUserProviderInterface $provider,
        private SignerInterface $signer,
        private JwtConfig $config,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $tokenId = is_array($body) ? ($body['refresh_token'] ?? null) : null;

        if (!is_string($tokenId) || $tokenId === '' || strlen($tokenId) > self::MAX_REFRESH_TOKEN_LENGTH) {
            return $this->invalidRequest();
        }

        // Preflight is deliberately non-authoritative. It lets the most common
        // provider/signing/response-allocation failures happen before the
        // bearer is irreversibly rotated; rotate() below still repeats all
        // credential-state checks under family serialization.
        $subjectId = $this->refreshManager->findActiveSubject($tokenId);

        if ($subjectId === null) {
            $result = $this->refreshManager->rotate($tokenId);

            if ($result instanceof DeniedReasonInterface) {
                return TokenResponseHeaders::apply(
                    $this->deniedResponseFactory->create($result),
                );
            }

            // A custom store that rotates after claiming the same token was not
            // active during preflight is internally inconsistent. Revoke the
            // unexpected successor rather than issuing credentials for it.
            $this->refreshManager->revoke($result->id);

            return TokenResponseHeaders::apply(
                $this->deniedResponseFactory->create(new InvalidRefreshToken()),
            );
        }

        $identity = $this->provider->findByUuid($subjectId);

        if ($identity === null || !$subjectId->equals($identity->uuid)) {
            $this->refreshManager->revoke($tokenId);

            return TokenResponseHeaders::apply(
                $this->deniedResponseFactory->create(new InvalidRefreshToken()),
            );
        }

        $now = $this->clock->now()->getTimestamp();
        $accessToken = $this->signer->sign(new Claims(
            subject: $identity->uuid->toString(),
            issuedAt: $now,
            expiresAt: $now + $this->config->accessTtl,
            issuer: $this->config->issuer,
            audience: $this->config->audience,
            type: $this->config->type,
        ));
        BearerCredential::assertValid($accessToken);
        $response = $this->responseFactory->createResponse(200);
        $result = $this->refreshManager->rotate($tokenId);

        if ($result instanceof DeniedReasonInterface) {
            return TokenResponseHeaders::apply(
                $this->deniedResponseFactory->create($result),
            );
        }

        if (!$subjectId->equals($result->subjectId)) {
            $this->refreshManager->revoke($result->id);

            return TokenResponseHeaders::apply(
                $this->deniedResponseFactory->create(new InvalidRefreshToken()),
            );
        }

        // The provider is application-owned mutable account state. Recheck it
        // after the serialized credential transition so a deletion/disablement
        // racing the preflight cannot receive a freshly rotated credential.
        try {
            $currentIdentity = $this->provider->findByUuid($result->subjectId);
        } catch (\Throwable $exception) {
            $this->refreshManager->revoke($result->id);
            throw $exception;
        }

        if (
            $currentIdentity === null
            || !$result->subjectId->equals($currentIdentity->uuid)
        ) {
            $this->refreshManager->revoke($result->id);

            return TokenResponseHeaders::apply(
                $this->deniedResponseFactory->create(new InvalidRefreshToken()),
            );
        }

        try {
            $response->getBody()->write(json_encode([
                'access_token' => $accessToken,
                'refresh_token' => $result->id,
                'token_type' => 'Bearer',
                'expires_in' => $this->config->accessTtl,
            ], JSON_THROW_ON_ERROR));

            return TokenResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            // The client never received the successor. Revoke its family so an
            // undisclosed active bearer cannot survive a response failure.
            $this->refreshManager->revoke($result->id);
            throw $exception;
        }
    }

    private function invalidRequest(): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(400);
        $response->getBody()->write(json_encode([
            'error' => 'invalid_refresh_token',
        ], JSON_THROW_ON_ERROR));

        return TokenResponseHeaders::apply($response);
    }
}
