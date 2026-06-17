<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\MagicLink;

use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkStrategy;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles magic link verification and issues a JWT token pair.
 *
 * Extracts the token via VerifyExtractor, verifies via
 * MagicLinkStrategy, and returns access + refresh tokens.
 */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private VerifyExtractor $extractor,
        private MagicLinkStrategy $strategy,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(json_encode(['error' => 'missing_token'], JSON_THROW_ON_ERROR));

            return $response->withHeader('Content-Type', 'application/json');
        }

        $result = $this->strategy->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        return $this->tokenPair->create($result->subject);
    }
}
