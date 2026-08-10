<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Auth\AuthSubject;

/** Worker-side processor. It must not run in the request thread. */
final readonly class TokenRequestProcessor
{
    public function __construct(
        private UserProviderInterface $provider,
        private TokenManagerInterface $tokenManager,
        private SenderInterface $sender,
    ) {}

    public function process(TokenRequest $request): void
    {
        $user = $this->provider->findByIdentity($request->identity);
        if ($user === null) {
            return;
        }
        $subjectId = (string) AuthSubject::id($user);
        $this->tokenManager->revokeForUser($subjectId);
        $token = $this->tokenManager->generate($subjectId);
        $this->sender->send(
            $request->destination ?? $request->identity,
            $token,
            $request->context,
        );
    }
}
