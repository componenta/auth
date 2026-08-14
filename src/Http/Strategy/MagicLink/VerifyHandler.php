<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\MagicLink;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\ReplacingPayloadStorage;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class VerifyHandler implements RequestHandlerInterface
{
    public function __construct(
        private VerifyExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private SessionManagerInterface $sessionManager,
        private ReplacingPayloadStorage $storage,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
        private SessionAttributeExtractorInterface $attributeExtractor = new SessionAttributeExtractor(),
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $payload = $this->extractor->extract($request);

        if ($payload === null) {
            return $this->json(400, ['error' => 'missing_token']);
        }

        // Complete request-derived and response-allocation work before the
        // one-time magic-link bearer can be consumed.
        $attributes = $this->attributeExtractor->extract($request);
        $response = $this->successResponse();
        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return MagicLinkResponseHeaders::apply(
                $this->deniedResponseFactory->create($result->subject),
            );
        }

        $session = $this->sessionManager->create(
            $result->subject->uuid,
            $attributes,
        );

        try {
            $stored = $this->storage->store(
                $request,
                $response,
                new SessionPayload($session->id),
            );

            return MagicLinkResponseHeaders::apply(
                $stored
                    ->withHeader('Content-Type', 'application/json')
                    ->withHeader('Cache-Control', 'no-store')
                    ->withHeader('Pragma', 'no-cache'),
            );
        } catch (\Throwable $exception) {
            // The magic-link token is already consumed and remains single-use;
            // only the unpublished server-side session is compensated.
            $this->sessionManager->terminate($session->id);
            throw $exception;
        }
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

    private function successResponse(): ResponseInterface
    {
        $response = $this->responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
        $response->getBody()->write('{}');

        return MagicLinkResponseHeaders::apply($response);
    }
}
