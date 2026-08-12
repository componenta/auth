<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\RememberMe;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\Strategy\Session\UserProviderInterface;
use Componenta\Auth\Http\Transport\SessionPayload;
use Componenta\Auth\RememberMe\RememberMeRotation;
use Componenta\Auth\RememberMe\RememberMeTokenManagerInterface;
use Componenta\Auth\Session\ConcurrentRegenerationException;
use Componenta\Auth\Session\SessionAttributeExtractor;
use Componenta\Auth\Session\SessionAttributeExtractorInterface;
use Componenta\Auth\Session\SessionInterface;
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
        return $payload instanceof SessionPayload
            && $payload->rememberMeToken !== null;
    }

    #[\Override]
    public function attempt(object $payload, ContextInterface $context): AuthenticationResult
    {
        /** @var SessionPayload $payload */
        $plainToken = $payload->rememberMeToken;

        if ($plainToken === null) {
            return $this->denied();
        }

        $rotation = $this->tokenManager->rotate($plainToken);

        if ($rotation === null) {
            return $this->denied();
        }

        $identity = $this->provider->findByUuid($rotation->subjectId);

        if (
            $identity === null
            || !$rotation->subjectId->equals($identity->uuid)
        ) {
            $this->tokenManager->revoke($rotation->successorToken);

            return $this->denied();
        }

        try {
            $session = $this->resolveSession($rotation, $context);
        } catch (ConcurrentRegenerationException|\InvalidArgumentException) {
            $this->tokenManager->revoke($rotation->successorToken);

            return $this->denied();
        } catch (\Throwable $exception) {
            $this->tokenManager->revoke($rotation->successorToken);

            throw $exception;
        }

        if (!$this->tokenManager->bindRotation($rotation, $session->id)) {
            $this->sessionManager->terminate($session->id);

            return $this->denied();
        }

        return new AuthenticationResult(
            subject: $identity,
            transportPayload: new SessionPayload(
                $session->id,
                $rotation->successorToken,
            ),
            session: $session,
        );
    }

    private function resolveSession(
        RememberMeRotation $rotation,
        ContextInterface $context,
    ): SessionInterface {
        $existing = $this->sessionManager->find($rotation->previousSessionId);

        if ($existing !== null) {
            return $this->sessionManager->regenerate($existing->id);
        }

        $request = $context->getAttribute(ServerRequestInterface::class);
        $attributes = $request instanceof ServerRequestInterface
            ? $this->attributeExtractor->extract($request)
            : [];

        return $this->sessionManager->create(
            $rotation->subjectId,
            $attributes,
        );
    }

    private function denied(): AuthenticationResult
    {
        return new AuthenticationResult(new InvalidCredentials());
    }
}
