<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Jwt\MagicLink;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\Strategy\Jwt\TokenPairResponse;
use Componenta\Auth\Http\Strategy\MagicLink\MagicLinkResponseHeaders;
use Componenta\Auth\Http\Strategy\MagicLink\VerifyExtractor;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Authenticates a POST-body magic-link payload through the configured authenticator. */
final readonly class TokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private VerifyExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private TokenPairResponse $tokenPair,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        if (strtoupper($request->getMethod()) !== 'POST') {
            return $this->json(405, ['error' => 'method_not_allowed'])
                ->withHeader('Allow', 'POST');
        }

        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $this->json(400, ['error' => 'missing_token']);
        }

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return MagicLinkResponseHeaders::apply(
                $this->deniedResponseFactory->create($result->subject),
            );
        }

        return MagicLinkResponseHeaders::apply(
            $this->tokenPair->create($result->subject),
        );
    }

    /** @param array<string, mixed> $payload */
    private function json(int $status, array $payload): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));

        return MagicLinkResponseHeaders::apply(
            $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache'),
        );
    }
}