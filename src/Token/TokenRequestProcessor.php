<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequestProcessor
{
    public function __construct(
        private UserProviderInterface $provider,
        private TokenManagerInterface $tokenManager,
        private SenderInterface $sender,
    ) {}

    public function process(TokenRequest $request): void
    {
        $identity = $this->provider->findByIdentity($request->identity);

        if ($identity === null) {
            return;
        }

        $subjectId = $identity->uuid->toString();
        $this->tokenManager->revokeForUser($subjectId);
        $token = $this->tokenManager->generate($subjectId);
        $this->sender->send(
            $request->destination ?? $request->identity,
            $token,
            $request->context,
        );
    }
}
