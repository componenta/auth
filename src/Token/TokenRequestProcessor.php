<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

/** Processes one explicit one-time-token purpose and rejects misrouted work. */
final readonly class TokenRequestProcessor
{
    public function __construct(
        private UserProviderInterface $provider,
        private TokenManagerInterface $tokenManager,
        private SenderInterface $sender,
        private string $purpose,
    ) {
        if (preg_match('/\A[a-z][a-z0-9._-]{0,63}\z/D', $this->purpose) !== 1) {
            throw new \InvalidArgumentException(
                'Token processor purpose must be a bounded machine-readable identifier.',
            );
        }
    }

    public function process(TokenRequest $request): void
    {
        if ($request->purpose !== $this->purpose) {
            throw new \InvalidArgumentException(sprintf(
                'Token request purpose "%s" cannot be processed by "%s".',
                $request->purpose,
                $this->purpose,
            ));
        }

        $identity = $this->provider->findByIdentity($request->identity);

        if ($identity === null) {
            return;
        }

        $plainToken = $this->tokenManager->replaceForSubject($identity->uuid);
        $this->sender->send(
            $request->identity,
            $plainToken,
            $request->context,
        );
    }
}
