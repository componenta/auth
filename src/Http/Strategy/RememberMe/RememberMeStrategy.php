<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\RememberMe;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Strategy\Session\UserProviderInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class RememberMeStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private RememberMeTokenManagerInterface $tokenManager,
        private SessionManagerInterface $sessionManager,
        private UserProviderInterface $provider,
        private SessionAttributeExtractorInterface $attributeExtractor = new SessionAttributeExtractor(),
    ) {}

    #[\Override]
    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof SessionPayload && $payload->rememberMeToken !== null;
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var SessionPayload $payload */
        $consumed = $this->tokenManager->consume($payload->rememberMeToken);

        if ($consumed === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        $identity = $this->provider->findById($consumed->userId);

        if ($identity === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        if ($consumed->sessionId !== null) {
            $this->sessionManager->terminate($consumed->sessionId);
        }

        $request = $context->getAttribute(ServerRequestInterface::class);
        $attributes = $request instanceof ServerRequestInterface
            ? $this->attributeExtractor->extract($request)
            : [];
        $session = $this->sessionManager->create($consumed->userId, $attributes);
        $newToken = $this->tokenManager->create($consumed->userId, $session->id);

        return new AuthenticationResult(
            subject: $identity,
            transportPayload: new SessionPayload($session->id, $newToken),
            session: $session,
        );
    }
}
