<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\Otp;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\Otp\OtpExtractor;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Authenticates an OTP payload through the configured authenticator. */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private OtpExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write(json_encode(
                ['error' => 'missing_credentials'],
                JSON_THROW_ON_ERROR,
            ));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        return $this->tokenPair->create($result->subject);
    }
}
