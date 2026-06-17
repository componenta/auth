<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles OTP code verification requests.
 *
 * Extracts destination and code from the request, verifies
 * via OtpStrategy, creates a session, and sets the session cookie.
 */
final readonly class VerifyHandler implements RequestHandlerInterface
{
    public function __construct(
        private OtpExtractor $extractor,
        private OtpStrategy $strategy,
        private SessionManagerInterface $sessionManager,
        private PayloadStorageInterface $storage,
        private DeniedResponseFactoryInterface $deniedResponseFactory,
        private ResponseFactoryInterface $responseFactory,
        private SessionAttributeExtractorInterface $attributeExtractor = new SessionAttributeExtractor(),
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

        $session = $this->sessionManager->create(
            AuthSubject::id($result->subject),
            $this->attributeExtractor->extract($request),
        );

        $response = $this->responseFactory->createResponse(200);
        $response = $this->storage->store($request, $response, new SessionPayload($session->id));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
