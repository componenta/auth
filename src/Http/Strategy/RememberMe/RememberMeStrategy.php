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

/**
 * Authenticates users via remember-me cookie.
 *
 * Supports SessionPayload with a remember-me token (both cookies present,
 * or only remember-me cookie with sessionId=null).
 *
 * On success: atomically consumes the token, creates new session
 * and new token, and returns transport payload for cookie update.
 */
final readonly class RememberMeStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private RememberMeTokenManagerInterface $tokenManager,
        private SessionManagerInterface $sessionManager,
        private UserProviderInterface $provider,
        private SessionAttributeExtractorInterface $attributeExtractor = new SessionAttributeExtractor(),
    ) {}

    public function supports(object $payload, ContextInterface $context): bool
    {
        return $payload instanceof SessionPayload && $payload->rememberMeToken !== null;
    }

    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var SessionPayload $payload */
        $consumed = $this->tokenManager->consume($payload->rememberMeToken);

        if ($consumed === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        $user = $this->provider->findById($consumed->userId);

        if ($user === null) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        // Terminate the old session first to avoid orphan sessions
        // if subsequent operations fail.
        if ($consumed->sessionId !== null) {
            $this->sessionManager->terminate($consumed->sessionId);
        }

        $request = $context->getAttribute(ServerRequestInterface::class);

        // Auto-login: create new session
        $attributes = $request !== null
            ? $this->attributeExtractor->extract($request)
            : [];

        $session = $this->sessionManager->create($consumed->userId, $attributes);

        // Create new token linked to the new session
        $newToken = $this->tokenManager->create($consumed->userId, $session->id);

        $user->currentSessionId = $session->id;

        return new AuthenticationResult(
            subject: $user,
            transportPayload: new SessionPayload($session->id, $newToken),
        );
    }
}
