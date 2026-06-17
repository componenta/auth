<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Handles password-based login requests.
 *
 * Extracts credentials, authenticates via PasswordStrategy,
 * creates a session, and delegates cookie management to transport.
 */
readonly class LoginHandler implements RequestHandlerInterface
{
    public function __construct(
        protected PasswordExtractor              $extractor,
        protected PasswordStrategy               $strategy,
        protected SessionManagerInterface        $sessionManager,
        protected PayloadStorageInterface        $storage,
        protected DeniedResponseFactoryInterface $deniedResponseFactory,
        protected ResponseFactoryInterface       $responseFactory,
        protected ?RememberMeTokenManagerInterface $tokenManager = null,
        protected SessionAttributeExtractorInterface $attributeExtractor = new \Componenta\Auth\Session\SessionAttributeExtractor(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);

        $result = $this->strategy->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        $subjectId = AuthSubject::id($result->subject);

        $session = $this->sessionManager->create(
            $subjectId,
            $this->attributeExtractor->extract($request),
        );

        $rememberMeToken = null;

        if ($payload->remember && $this->tokenManager !== null) {
            $rememberMeToken = $this->tokenManager->create($subjectId, $session->id);
        }

        $response = $this->responseFactory->createResponse(200);

        return $this->storage->store($request, $response, new SessionPayload($session->id, $rememberMeToken));
    }
}
