<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Password;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LoginHandler implements RequestHandlerInterface
{
    public function __construct(
        protected PasswordExtractor $extractor,
        protected AuthenticatorInterface $authenticator,
        protected SessionManagerInterface $sessionManager,
        protected PayloadStorageInterface $storage,
        protected DeniedResponseFactoryInterface $deniedResponseFactory,
        protected ResponseFactoryInterface $responseFactory,
        protected ?RememberMeTokenManagerInterface $tokenManager = null,
        protected SessionAttributeExtractorInterface $attributeExtractor = new SessionAttributeExtractor(),
    ) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $payload = $this->extractor->extract($request);
        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponseFactory->create($result->subject);
        }

        $subjectId = $result->subject->uuid;
        $session = $this->sessionManager->create(
            $subjectId,
            $this->attributeExtractor->extract($request),
        );
        $rememberMeToken = $payload->remember && $this->tokenManager !== null
            ? $this->tokenManager->create($subjectId, $session->id)
            : null;
        $response = $this->responseFactory->createResponse(200);

        return $this->storage->store(
            $request,
            $response
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache'),
            new SessionPayload($session->id, $rememberMeToken),
        );
    }
}
