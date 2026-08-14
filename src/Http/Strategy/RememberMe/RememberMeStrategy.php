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
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof SessionPayload
            && $payload->rememberMeToken !== null;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        /** @var SessionPayload $payload */
        $plainToken = $payload->rememberMeToken;

        if ($plainToken === null) {
            return $this->denied();
        }

        $rotation = $this->tokenManager->rotate($plainToken);

        if ($rotation === null) {
            return $this->denied();
        }

        try {
            $identity = $this->provider->findByUuid($rotation->subjectId);
        } catch (\Throwable $exception) {
            // The successor is already the only valid bearer but has not been
            // returned to the client. Do not leave it active after provider
            // infrastructure fails.
            $this->tokenManager->revoke($rotation->successorToken);
            throw $exception;
        }

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

        try {
            $bound = $this->tokenManager->bindRotation(
                $rotation,
                $session->id,
            );
        } catch (\Throwable $exception) {
            $this->rollbackUnpublishedRotation($rotation, $session);
            throw $exception;
        }

        if (!$bound) {
            $this->rollbackUnpublishedRotation($rotation, $session);

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
        #[\SensitiveParameter]
        RememberMeRotation $rotation,
        #[\SensitiveParameter]
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

    /**
     * The newly created/regenerated session and successor remember bearer have
     * not been published to the client. Revoke both on a bind failure. A
     * cleanup failure is intentionally not swallowed because it can leave
     * credential state active and requires operator attention.
     */
    private function rollbackUnpublishedRotation(
        #[\SensitiveParameter]
        RememberMeRotation $rotation,
        #[\SensitiveParameter]
        SessionInterface $session,
    ): void {
        try {
            $this->tokenManager->revoke($rotation->successorToken);
        } finally {
            $this->sessionManager->terminate($session->id);
        }
    }

    private function denied(): AuthenticationResult
    {
        return new AuthenticationResult(new InvalidCredentials());
    }
}
