<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Otp;

use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Componenta\Auth\Http\Strategy\Otp\OtpStrategy;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles OTP code verification and issues a JWT token pair.
 *
 * Extracts destination and code via OtpExtractor, verifies
 * via OtpStrategy, and returns access + refresh tokens.
 */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private OtpExtractor $extractor,
        private OtpStrategy $strategy,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(
                json_encode(['error' => 'missing_credentials'], JSON_THROW_ON_ERROR)
            );

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
